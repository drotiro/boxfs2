#ifndef BOXPATH_H
#define BOXPATH_H

/* 2009-10-20 Domenico Rotiroti
   Licensed under the GPLv2

   This file contains all the path-related types
   and functions.
*/

#include <libxml/hash.h>
#include <pthread.h>
#include <time.h>
#include <libapp/list.h>

#include "boxjson.h"

#ifndef TRUE
#define TRUE  1
#define FALSE 0
#endif

/* Data types */
typedef struct boxdir_t
{
  list * folders, * files, * pieces;
  char * id;
  pthread_mutex_t * dirmux;
} boxdir;

typedef struct boxfile_t
{
  char * name;
  long long size;
  char * id;
  time_t ctime;
  time_t mtime;
} boxfile;

typedef struct boxpath_t
{
  boxdir  * dir;
  char    * base;
  boxfile * file;
  int	    is_dir;
} boxpath;

typedef xmlHashTablePtr boxtree;

/* Externals */
extern boxtree allDirs;

/* Manipulation functions */
boxpath *       boxpath_from_string(const char * path);
void		boxpath_free(boxpath * bpath);
int 		boxpath_getfile(boxpath * bpath);
int		boxpath_removefile(boxpath * bpath);
int		boxpath_renamefile(boxpath * bpath, const char * newname);

/* Large files */
list_iter	boxpath_first_part(boxpath * bpath);
list_iter	boxpath_next_part(boxpath * bpath, list_iter it);

/* Tree handling */
void 		boxtree_init(jobj * root, jobj * info);
boxdir *	boxtree_add_folder(const char * path, const char * id, jobj * folder);
void		boxtree_movedir(const char * from, const char * to);

/* Other utilities */
boxdir *	boxdir_create();
boxfile *       boxfile_create(const char * base);
int filename_compare(void * p1, void * p2); //comparator for list of boxfile*

#endif
//BOXPATH_H
