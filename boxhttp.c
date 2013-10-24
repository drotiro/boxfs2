/**************************
 Licensed under the GPLv2
**************************/

#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>

#include "boxhttp.h"
#include "boxopts.h"

#define MAXBUF 4096
#define DATABUF 32768
//#define DATABUF 4096

static struct curl_slist *headers = NULL;

typedef struct edata_t {
	char * data;
	size_t len;
	size_t capacity;
} edata;

void edata_init(edata * e) {
	e->data = malloc(DATABUF);
	e->data[0] = 0;
	e->capacity = DATABUF;
	e->len = 0;
}

void edata_cat(edata * e, char * txt, size_t size)
{
	if((e->len+size) >= e->capacity) {
		//printf("old size: %d, new size: %d\n", e->capacity, e->capacity+DATABUF);
		e->data = realloc(e->data, e->capacity+DATABUF);
		e->capacity+=DATABUF;
	}
	
	memcpy(e->data+e->len, txt, size);
	e->len+=size;
	e->data[e->len] = 0;
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
	struct curl_slist *h=NULL;
	CURL * curl;

	curl = curl_easy_init();
	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	if(headers) curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	
	return curl;
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
  CURLcode res = -1;
  edata e;
  

  edata_init(&e);
  curl = my_curl_init(url);
  if(curl) {
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fetch_append);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &e);
    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }
  
  return e.data;
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

    curl_easy_cleanup(curl);
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
	CURLcode res = -1;
	edata e;

	edata_init(&e);
	curl = my_curl_init(url);
	if(curl) {
		curl_easy_setopt(curl, CURLOPT_HTTPPOST, pd->post);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fetch_append);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &e);
		res = curl_easy_perform(curl);
		curl_easy_cleanup(curl);
	}

	return e.data;
}

char * http_postfile(const char * url, postdata_t pd)
{
  CURL *curl;
  CURLcode res = -1;
  edata e;

  edata_init(&e);
  curl = my_curl_init(url);
  if(curl) {
	curl_easy_setopt(curl, CURLOPT_HTTPPOST, pd->post);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fetch_append);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &e);
    res = curl_easy_perform(curl);

    curl_easy_cleanup(curl);
  }

  return e.data;
}
