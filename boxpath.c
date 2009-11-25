/*************************************

  DR: Local file-tree representation
      data structures and functions

  This software is licensed under the 
  GPLv2 license.

*************************************/

#include "boxpath.h"

#include <string.h>
#include <libgen.h>
#include <errno.h>
#include <libxml/list.h>

boxtree allDirs = NULL;

boxpath *       boxpath_from_string(const char * path)
{
	char * dir = dirname(strdup(path));
	char * file = basename(strdup(path));
        boxpath * bpath = (boxpath*) malloc(sizeof(boxpath));
  
	bpath->dir = xmlHashLookup(allDirs, dir);
	bpath->base = strdup(file);
	bpath->file = NULL;
	bpath->is_dir = (xmlHashLookup(allDirs, path)!=NULL);

	free(dir);
	//free(file); // This crashes boxfs. WHY???
	return bpath; 
}

void	boxpath_free(boxpath * bpath)
{
	if(!bpath) return;
	if(bpath->base) free(bpath->base);
	free(bpath);
}


/* boxpath_getfile and helper
   used to fill boxpath->file data
*/

int walk_getfile(boxfile * aFile, boxfile ** info)
{
  if(!strcmp(aFile->name,(*info)->name)) {
    free(*info);
    *info = aFile;
    return 0;
  }

  return 1;
}

int boxpath_getfile(boxpath * bpath)
{
	boxfile * aFile = malloc(sizeof(boxfile));
	aFile->name = bpath->base;
	aFile->size = -EINVAL;
	xmlListWalk((bpath->is_dir ? bpath->dir->folders : bpath->dir->files),
		(xmlListWalker)walk_getfile, &aFile);
	if(aFile->size!=-EINVAL) {
		bpath->file = aFile;
		return TRUE;
	} else {
		free(aFile);
		return FALSE;
	}
}

