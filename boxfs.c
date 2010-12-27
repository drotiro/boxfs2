/*
    BOXFS: A FUSE-based filesystem to access a box.net account.
        This file is based on fusexmp.c by Miklos Szeredi
  
  This software is licensed under the GPLv2 license.
*/

#define FUSE_USE_VERSION 26

#ifdef linux
/* For pread()/pwrite() */
#define _XOPEN_SOURCE 500
#endif

#include <fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>

#include "boxapi.h"

#define CAST_PATH (char*)(ptrdiff_t)

static int box_access(const char *path, int mask)
{
    return 0;
}


static int box_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
                       off_t offset, struct fuse_file_info *fi)
{
    return api_readdir(path,filler,buf);
}

static int box_mkdir(const char *path, mode_t mode)
{
  return api_createdir(path);
}

static int box_release(const char *path, struct fuse_file_info *fi)
{
    if(fi->flags & (O_RDWR | O_WRONLY)) {
      api_upload(path,CAST_PATH fi->fh);
    }
    unlink(CAST_PATH fi->fh);
    free(CAST_PATH fi->fh);
    return 0;
}


static int box_truncate(const char *path, off_t size)
{
  int res = 0;
  int fd;
  //char * fullpath;
  char * lpeer = NULL;
 
  // uploading an empty file doesn't work.
  if(size==0) {
    res = api_removefile(path);
    api_create(path);
    return res;
  }
 
  // download file locally, truncate and re-upload it
  lpeer = strdup("/tmp/bpfXXXXXX");
  fd = mkstemp(lpeer);
  if(fd!=-1) close(fd);
  res = api_open(path, lpeer);               
  if(!res) {
    res = truncate(lpeer, size);
    api_upload(path, lpeer);
  } else res = -ENOENT;
  free(lpeer);
  
  return res;
}

static int box_utimens(const char *path, const struct timespec ts[2])
{
    int res;
    struct timeval tv[2];

    tv[0].tv_sec = ts[0].tv_sec;
    tv[0].tv_usec = ts[0].tv_nsec / 1000;
    tv[1].tv_sec = ts[1].tv_sec;
    tv[1].tv_usec = ts[1].tv_nsec / 1000;

    res = utimes(path, tv);
    if (res == -1)
        return -errno;

    return 0;
}

static int box_open(const char *path, struct fuse_file_info *fi)
{
    int res;
    int fd;
    char * lpeer = NULL;
    
    lpeer = strdup("/tmp/bpfXXXXXX");
    fd = mkstemp(lpeer);
    if(fd!=-1) close(fd);
    res = api_open(path, lpeer);
    fi->fh = (unsigned long)lpeer; //it's not nice, but this is the way.
    
    return res;
}

static int box_create(const char * path, mode_t mode, struct fuse_file_info * fi)
{
    int fd;
    char * lpeer = NULL;
      
    lpeer = strdup("/tmp/bUfXXXXXX");
    fd = mkstemp(lpeer);
        
    if (fd == -1){
	free(lpeer);
	return -errno;
    }
    close(fd);

    fi->fh = (unsigned long)lpeer;                  
    api_create(path);
    return 0;
}

static int box_read(const char *path, char *buf, size_t size, off_t offset,
                    struct fuse_file_info *fi)
{
    int fd;
    int res;

    fd = open(CAST_PATH fi->fh, O_RDONLY);
    if (fd == -1)
        return -errno;

    res = pread(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    close(fd);
    return res;
}

static int box_write(const char *path, const char *buf, size_t size,
                     off_t offset, struct fuse_file_info *fi)
{
    int fd;
    int res;
    char * tmpf;

    tmpf = CAST_PATH fi->fh;
    fd = open(tmpf, O_WRONLY);
    if (fd == -1)
        return -errno;

    res = pwrite(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    close(fd);
    return res;
}

static int box_statfs(const char *path, struct statvfs *stbuf)
{
    long tot_space, used_space;
    
    api_getusage(&tot_space, &used_space);
    stbuf->f_bsize = stbuf->f_frsize = 1;
    stbuf->f_blocks = tot_space;
    stbuf->f_bfree = stbuf->f_bavail = (tot_space - used_space);

    return 0;
}

/*
 * Fuse operations for boxfs.
 * Most box_* functions just wrap their corresponding 'api_'
 * converting parameters and/or performing local I/O.
 */
static struct fuse_operations box_oper = {
    .getattr	= api_getattr,
    .access	= box_access,
    .readdir	= box_readdir,
    .mkdir	= box_mkdir,
    .unlink	= api_removefile,
    .rmdir	= api_removedir,
    .release	= box_release,
    .rename	= api_rename_v2,
    .truncate	= box_truncate,
    .utimens	= box_utimens,
    .open	= box_open,
    .create	= box_create,
    .read	= box_read,
    .write	= box_write,
    .statfs	= box_statfs,
};



int main(int argc, char *argv[])
{
    int fuse_res;

    if(api_init(&argc, &argv)) return 1;
    fuse_res = fuse_main(argc, argv, &box_oper, NULL);
    api_free();
     
    return fuse_res;   
}
