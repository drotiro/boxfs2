#ifndef BOXAPI_H
#define BOXAPI_H

/*
  This software is licensed under the
    GPLv3 license.
*/

#define FUSE_USE_VERSION 26

#include <fuse.h>

void 	api_free(); 
int 	api_init(int* argc, char*** argv);

int 	api_readdir(const char *, fuse_fill_dir_t, void * buf);
void	api_getusage(long long *, long long * );

int	api_open(const char *, const char *);
int 	api_getattr(const char *path, struct stat *stbuf);
void	api_upload(const char *,  const char *);
int	api_create(const char *);
int	api_createdir(const char *);
int	api_removefile(const char *);
int	api_removedir(const char *);
int     api_rename_v2(const char *, const char *);

int     ends_with(const char * str, const char * suff);


/* Some constant and utility define */
#define BOX_ERR(MSG) fprintf(stderr,MSG)
#define FALSE 0
#define TRUE  1
//#define PROTO_HTTP  "http"
//#define PROTO_HTTPS "https"
#define PART_SUFFIX "BF#"
#define PART_SUFFIX_LEN 3
#define PART_LEN    (200*1024*1024)
#define MIN(A,B) (A<B ? A : B)

/* globals needed almost everywhere */
extern char * auth_token, * refresh_token;

#endif
// BOXAPI_H


