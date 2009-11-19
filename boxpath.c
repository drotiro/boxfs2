#include "boxpath.h"

#include <string.h>
#include <libgen.h>

boxtree allDirs = NULL;

boxpath *       boxpath_from_string(const char * path)
{
	boxpath * bpath = (boxpath*) malloc(sizeof(boxpath));
	char * dir = dirname(strdup(path));
	char * file = basename(strdup(path));
  	
	bpath->dir = xmlHashLookup(allDirs,dir);
	bpath->base = file;

	free(dir); 
}


void	boxpath_free(boxpath * bpath)
{
	if(!bpath) return;
	if(bpath->base) free(bpath->base);
	free(bpath);
}

