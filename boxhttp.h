#ifndef BOXHTTP_H
#define BOXHTTP_H

/* 2010-02-03 Domenico Rotiroti
   Licensed under the GPLv2

   HTTP(S) transfer functions and related utilities
*/

/* A type for data to be posted */
typedef char * postdata_t;
postdata_t	post_init();
void		post_free(postdata_t postdata);

/* Fetching (GET) of pages and files */
char *	http_fetch(const char * url);
int		http_fetch_file(const char * url, const char * dest);

/* Data POSTing */
void post_add(postdata_t buf, const char * name, const char * val);
long post_addfile(postdata_t * rbuf, const char * name, const char * tmpfile, long fsize);
void http_post(const char * url, postdata_t data);
char * http_postfile(const char * url, postdata_t data, long size);


#endif
//BOXHTTP_H
