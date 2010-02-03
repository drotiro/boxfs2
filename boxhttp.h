#ifndef BOXHTTP_H
#define BOXHTTP_H

/* 2010-02-03 Domenico Rotiroti
   Licensed under the GPLv2

   HTTP(S) transfer functions and related utilities
*/


/* Fetching (GET) of pages and files */
char *	http_fetch(const char * url);
int		http_fetch_file(const char * url, const char * dest);

/* Data POSTing */
void post_add(char * buf, const char * name, const char * val);
long post_addfile(char ** rbuf, const char * name, const char * tmpfile, long fsize);
void http_post(const char * url, const char * data);
char * http_postfile(const char * url, const char * data, long size);


#endif
//BOXHTTP_H
