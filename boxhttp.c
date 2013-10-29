/**************************
 Licensed under the GPLv3
**************************/

#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>

#include "boxhttp.h"
#include "boxopts.h"
#include "boxutils.h"

#define MAXBUF 4096

static struct curl_slist *headers = NULL;
/* Don't share this between threads! */
static CURL * conn = NULL; 
static int conn_reuse = 0;

void set_conn_reuse(int reuse)
{
	conn_reuse = reuse;
	if(!reuse) {
		curl_easy_cleanup(conn);
		conn = NULL;
	}
}

/* Take care of Authentication header */
void update_auth_header(const char * auth_token)
{
	struct curl_slist * hnew = NULL;
	char header[96] = "Authorization: Bearer ";

	if(auth_token) {
		strncat(header, auth_token, 32);
		hnew = curl_slist_append(hnew, header);
	}

	if(headers) curl_slist_free_all(headers);
	headers = hnew;
}

/* cURL initialization with common options */
CURL * my_curl_init(const char * url)
{
	CURL * curl;

	if(conn_reuse && conn) {
		curl_easy_setopt(conn, CURLOPT_URL, url);
		return conn;
	}
	
	curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	if(headers) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	
	if(conn_reuse) conn = curl;
	return curl;
}

void my_curl_cleanup(CURL * curl)
{
	if(!conn_reuse) curl_easy_cleanup(curl);
}

postdata_t post_init()
{
  postdata_t pd = malloc(sizeof(struct postdata));
  pd->post = NULL;
  pd->last = NULL;
  return pd;
}

void post_free(postdata_t postdata)
{
  curl_formfree(postdata->post);
  free(postdata);
}

size_t throw_data(void * data, size_t size, size_t nmemb, void * stream)
{
  return size*nmemb; 
}

size_t fetch_append(void * data, size_t size, size_t nmemb, void * stream)
{
  edata * e = (edata*) stream;
  edata_cat(e, data, size*nmemb);
  return size*nmemb; 
}

char * http_fetch(const char * url)
{
	CURL *curl;
	//CURLcode res = -1;
	edata e;


	edata_init(&e);
	curl = my_curl_init(url);
	if(curl) {
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fetch_append);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &e);
		/*res = */curl_easy_perform(curl);
		my_curl_cleanup(curl);
	}

	return e.data;
}

long http_delete(const char * url)
{
	CURL *curl;
	CURLcode res = -1;
	long sc = 500;


	curl = my_curl_init(url);
	if(curl) {
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST,"DELETE");
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, throw_data);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, NULL);
		res = curl_easy_perform(curl);
		if(res==0) curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &sc);
		my_curl_cleanup(curl);
	}

	return sc;
}

char *  http_fetchf(const char * fmt, ...)
{
	char gkurl[MAXBUF];
	va_list ap;
	
	va_start(ap, fmt);
	vsprintf(gkurl, fmt, ap);
	va_end(ap);
	return http_fetch(gkurl);
}

int http_fetch_file(const char * url, const char * dest, int append)
{
  CURL *curl;
  CURLcode res = -1;
  FILE * fout;
  double dt;

  curl = my_curl_init(url);
  if(curl) {
    fout = fopen(dest, append ? "a": "w");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fout);
    res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_TOTAL_TIME, &dt);
    if(options.verbose) syslog(LOG_DEBUG, "Url %s fetched in %f seconds", url, dt);

    my_curl_cleanup(curl);
    fclose(fout);
  }
  return res;
}

void post_add(postdata_t buf, const char * name, const char * val)
{
	curl_formadd(&buf->post, &buf->last, 
		CURLFORM_COPYNAME, name,
		CURLFORM_COPYCONTENTS, val,
		CURLFORM_END);
}

long post_addfile(postdata_t pd, const char * name, const char * tmpfile)
{
  curl_formadd(&pd->post, &pd->last,
    CURLFORM_COPYNAME, "new_file0",
    CURLFORM_FILENAME, name,
    CURLFORM_FILE, tmpfile,
    CURLFORM_END);
  return 0;
}

char * post_addfile_part(postdata_t pd, const char * name,
        const char * tmpfile, size_t offset, size_t len)
{
    char * buf = (char*) malloc(len);
    FILE * tf = fopen(tmpfile, "r");
    fseek(tf, offset, SEEK_SET);
    fread(buf, 1, len, tf);
    fclose(tf);
    curl_formadd(&pd->post, &pd->last,
        CURLFORM_COPYNAME, "new_file0",
        CURLFORM_BUFFER , name,
        CURLFORM_BUFFERPTR, buf,
        CURLFORM_BUFFERLENGTH, len,
        CURLFORM_END);
    return buf;
}


char * http_post(const char * url, postdata_t pd)
{
	CURL *curl;
	//CURLcode res = -1;
	edata e;

	edata_init(&e);
	curl = my_curl_init(url);
	if(curl) {
		curl_easy_setopt(curl, CURLOPT_HTTPPOST, pd->post);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fetch_append);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &e);
		/*res = */curl_easy_perform(curl);
		my_curl_cleanup(curl);
	}

	return e.data;
}

char * do_http_with_fields(const char * url, const char * fields, const char * method)
{
	CURL *curl;
	//CURLcode res = -1;
	edata e;

	edata_init(&e);
	curl = my_curl_init(url);
	if(curl) {
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST,method);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, fields);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fetch_append);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &e);
		/*res = */curl_easy_perform(curl);
		my_curl_cleanup(curl);
	}

	return e.data;
}

char * http_post_fields(const char * url, const char * fields)
{
	return do_http_with_fields(url, fields, "POST");
}

char * http_put_fields(const char * url, const char * fields)
{
	return do_http_with_fields(url, fields, "PUT");
}

char * http_postfile(const char * url, postdata_t pd)
{
	CURL *curl;
	//CURLcode res = -1;
	edata e;

	edata_init(&e);
	curl = my_curl_init(url);
	if(curl) {
		curl_easy_setopt(curl, CURLOPT_HTTPPOST, pd->post);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fetch_append);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &e);
		/*res = */curl_easy_perform(curl);
		my_curl_cleanup(curl);
	}

	return e.data;
}
