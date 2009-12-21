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
#include <syslog.h>
#include <libxml/list.h>

boxtree allDirs = NULL;
boxfile * rootDir = NULL;

boxpath *       boxpath_from_string(const char * path)
{
	char * dir = dirname(strdup(path));
	char * file = basename(strdup(path));
        boxpath * bpath = (boxpath*) malloc(sizeof(boxpath));
  
	bpath->dir = xmlHashLookup(allDirs, dir);
	bpath->base = strdup(file);
	bpath->file = (strcmp(path,"/") ? NULL : rootDir);
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
	boxfile * aFile = NULL;

	/* check for obvious cases */	
	if(!bpath) return FALSE;
	if(bpath->file) return TRUE;
	/* do the search */
	aFile = malloc(sizeof(boxfile));
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

int boxpath_removefile(boxpath * bpath)
{
	if(!boxpath_getfile(bpath)) return FALSE;

	return xmlListRemoveFirst(
		bpath->is_dir ? bpath->dir->folders : bpath->dir->files,
		bpath->file);
}

/* boxpath_setup_tree and helpers
   used at mount time to fill the allDirs hash
*/

extern boxdir * create_dir();

void parse_dir(const char * path, xmlNode * node, const char * id)
{
  xmlNodePtr cur_node, cur_file, cur_dir;
  xmlAttrPtr attrs;
  boxdir * aDir;
  boxfile * aFile;
  char * newPath;
  int plen = strlen(path);

  aDir = create_dir();

  for (cur_node = node->children; cur_node; cur_node = cur_node->next) {
    if(!strcmp(cur_node->name,"files")) {
      for (cur_file = cur_node->children; cur_file; cur_file = cur_file->next) {
        //get name and append to files
        aFile = (boxfile *) malloc(sizeof(boxfile));
        for (attrs = cur_file->properties; attrs; attrs = attrs->next) {
          if(!strcmp(attrs->name,"file_name")) aFile->name = strdup(attrs->children->content);
          else if(!strcmp(attrs->name,"size")) aFile->size = atol(attrs->children->content);
          else if(!strcmp(attrs->name,"id")) aFile->id = strdup(attrs->children->content);
          else if(!strcmp(attrs->name,"created")) aFile->ctime = atol(attrs->children->content);
          else if(!strcmp(attrs->name,"updated")) aFile->mtime = atol(attrs->children->content);
        }
        xmlListPushBack(aDir->files,aFile);
      }
    } else if(!strcmp(cur_node->name,"folders")) {
      for (cur_dir = cur_node->children; cur_dir; cur_dir = cur_dir->next) {
        //get name and do recursion
        aFile = (boxfile *) malloc(sizeof(boxfile));
	aFile->size = 0;
        for (attrs = cur_dir->properties; attrs; attrs = attrs->next) {
          if(!strcmp(attrs->name,"name")) aFile->name = strdup(attrs->children->content);
          else if(!strcmp(attrs->name,"id")) aFile->id = strdup(attrs->children->content);
	  else if(!strcmp(attrs->name,"size")) aFile->size = atol(attrs->children->content);
          else if(!strcmp(attrs->name,"created")) aFile->ctime = atol(attrs->children->content);
          else if(!strcmp(attrs->name,"updated")) aFile->mtime = atol(attrs->children->content);
        }
        xmlListPushBack(aDir->folders,aFile);

        newPath = (char *) malloc(plen + strlen(aFile->name) + 2);
        sprintf(newPath, (plen==1 ? "%s%s" : "%s/%s"), path, aFile->name);
        parse_dir(newPath, cur_dir, aFile->id);
        free(newPath);
        free(aFile->id);
      }
    }
    /* skipping tags & sharing info */
  }

  aDir->id = strdup(id);
  xmlHashAddEntry(allDirs, path, aDir);
}

void setup_root_dir(xmlNode * cur_node) {
	xmlAttrPtr attrs;

	rootDir = (boxfile*) malloc(sizeof(boxfile));
	rootDir->size = 0;
	rootDir->name = strdup("/");
	for (attrs = cur_node->properties; attrs; attrs = attrs->next) {
		if(!strcmp(attrs->name,"created")) rootDir->ctime = atol(attrs->children->content);
		else if(!strcmp(attrs->name,"updated")) rootDir->mtime = atol(attrs->children->content);
		else if(!strcmp(attrs->name,"size")) rootDir->size = atol(attrs->children->content);
	}
}

void boxtree_setup(const char * treefile)
{
  xmlDoc *doc = NULL;
  xmlNode *root_element = NULL;
  xmlNode *cur_node = NULL;

  allDirs = xmlHashCreate(250);
  doc = xmlParseFile(treefile);
  root_element = xmlDocGetRootElement(doc);
  // raggiungiamo il nodo response--->tree->folder
  cur_node = root_element->children;
  while(strcmp(cur_node->name,"tree")) cur_node = cur_node->next; //skip status
  cur_node = cur_node->children;
  setup_root_dir(cur_node);
  parse_dir("/",cur_node,"0");

  xmlFreeDoc(doc);

}

