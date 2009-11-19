#ifndef BOXPATH_H
#define BOXPATH_H

/* 2009-10-20 Domenico Rotiroti
   Licensed under the GPLv2

   This file contains all the path-related types
   and functions.
*/

#include <libxml/hash.h>
#include <pthread.h>

/* Data types */
typedef struct boxdir_t
{
  xmlListPtr folders;
  xmlListPtr files;
  char * id;
  pthread_mutex_t * dirmux;
} boxdir;

typedef struct boxfile_t
{
  char * name;
  long size;
  char * id;
} boxfile;

typedef struct boxpath_t
{
  boxdir  * dir;
  char    * base;
  boxfile * file;
} boxpath;

typedef xmlHashTablePtr boxtree;

/* Externals */
extern boxtree allDirs;

/* Manipulation functions */
boxpath *	boxpath_from_string(const char * path);
void		boxpath_free(boxpath * bpath);

#endif
//BOXPATH_H
