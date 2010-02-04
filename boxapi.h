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
int api_rename(const char *, const char *);
#endif
// BOXAPI_H


