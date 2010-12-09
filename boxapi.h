#ifndef BOXAPI_H
#define BOXAPI_H

/*
  This software is licensed under the
    GPLv2 license.
*/

#include <fuse.h>

void 	api_free(); 
int 	api_init(int* argc, char*** argv);

int 	api_readdir(const char *, fuse_fill_dir_t, void * buf);
void	api_getusage(long *, long * );

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
#define PROTO_HTTP  "http"
#define PROTO_HTTPS "https"
#define PART_SUFFIX "BF#"
#define PART_SUFFIX_LEN 3
// DEBUG: PART_LEN should be 20Mb at least!
#define PART_LEN    (5*1024*1024)
#define MIN(A,B) (A<B ? A : B)

#endif
// BOXAPI_H


