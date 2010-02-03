/**************************
 Licensed under the GPLv2
**************************/

#include <libxml/nanohttp.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "boxhttp.h"

#define MAXBUF 4096

postdata_t post_init()
{
 return malloc(MAXBUF);
}

void post_free(postdata_t postdata)
{
 free(postdata);
}

char * http_fetch(const char * url)
{
  void * ctx;
  int len = 0;
  char * buf = NULL, *ct;

  ctx = xmlNanoHTTPOpen(url, &ct);
  if(!ctx) {
    //syslog(LOG_ERR, "Connection problem fetching url %s",url);
  } else {
    len = xmlNanoHTTPContentLength(ctx);
    if(len <= 0) len = MAXBUF;
    buf = (char*)malloc(len);
    len = xmlNanoHTTPRead(ctx,buf,len);
    buf[len] = 0;
    xmlNanoHTTPClose(ctx);
  }

  return buf;
}

int http_fetch_file(const char * url, const char * dest)
{
  void * ctx;
  int res = 1;
  char *ct;

  ctx = xmlNanoHTTPOpen(url, &ct);
  if(!ctx) {
    //syslog(LOG_ERR, "Connection problem fetching url %s",url);
  } else {
    res = xmlNanoHTTPSave(ctx, dest);
  }

  return res;
}

void post_add(postdata_t buf, const char * name, const char * val)
{
  sprintf(buf+strlen(buf),"--BfsBy\ncontent-disposition: form-data; name=\"%s\"\n\n%s\n",
        name, val);
}

long post_addfile(postdata_t * rbuf, const char * name, const char * tmpfile, long fsize)
{
  FILE * tf;
  int hlen;
  char * buf = NULL;
  long bufsize = fsize+256+strlen(name);
  
  buf = malloc(bufsize);
  if(!buf) { 
    //syslog(LOG_ERR, "Cannot allocate %ld bytes of memory",bufsize);
    *rbuf = NULL;
    return -1;
  }
  buf[0]=0;
  *rbuf=buf;
  
  sprintf(buf,"--BfsBy\ncontent-disposition: form-data; name=\"new_file0\"; filename=\"%s\"\n"
            "Content-Type: application/octet-stream\nContent-Transfer-Encoding: binary\n\n", name);
  hlen = strlen(buf);
  tf = fopen(tmpfile,"r");
  fread(buf+hlen, 1, fsize, tf);
  fclose(tf);
  memcpy(buf+hlen+fsize,"\n--BfsBy--\n\0",12);
  return fsize+hlen+11;  
}


void http_post(const char * url, postdata_t data)
{
  void * ctx;
  char contentType[512] = "multipart/form-data, boundary=BfsBy";
  char * ct = contentType;
  
  ctx = xmlNanoHTTPMethod(url, "POST", data, &ct, 
        NULL, strlen(data));
  xmlNanoHTTPClose(ctx);
  free(ct);
}

char * http_postfile(const char * url, postdata_t data, long size)
{
  void * ctx;
  int len = 0;
  char contentType[512] = "multipart/form-data, boundary=BfsBy";
  char * ct = contentType;
  char * buf;

  ctx = xmlNanoHTTPMethod(url, "POST", data, &ct,
        NULL, size);
        
  len = xmlNanoHTTPContentLength(ctx);
  //fprintf(stderr, "Response content length: %d\n",len);
  if(len <= 0) len = MAXBUF;
  buf = (char*)malloc(len);
  len = xmlNanoHTTPRead(ctx,buf,len);
  buf[len] = 0;
  xmlNanoHTTPClose(ctx);
  free(ct);
  //fprintf(stderr,"RESPONSE:\n%s\n",buf);

  return buf;  
}
                                             