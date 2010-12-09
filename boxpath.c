/*************************************

  DR: Local file-tree representation
      data structures and functions

  This software is licensed under the 
  GPLv2 license.

*************************************/

#include "boxpath.h"
#include "boxapi.h"
#include "boxopts.h"

#include <string.h>
#include <libgen.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>
#include <libxml/list.h>

#define DIR_HASH_SIZE	1001

boxtree allDirs = NULL;
boxfile * rootDir = NULL;

boxdir * boxdir_create()
{
  boxdir * aDir;
  aDir = (boxdir *) malloc(sizeof(boxdir));
  aDir->files = list_new(); // TODO: Deallocator!
  aDir->folders = list_new();
  aDir->pieces = list_new();
  aDir->dirmux = malloc(sizeof(pthread_mutex_t));
  pthread_mutex_init(aDir->dirmux, NULL);
  
  return aDir;
}

boxfile * boxfile_create(const char * base)
{
    boxfile * aFile;
    time_t now = time(NULL);
    
    aFile = (boxfile *) malloc(sizeof(boxfile));
    aFile->name = strdup(base);
    aFile->size = 0;
    aFile->id = NULL;
    aFile->ctime = now;
    aFile->mtime = now;

    return aFile;
}


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
	return bpath; 
}

void	boxpath_free(boxpath * bpath)
{
	if(!bpath) return;
	if(bpath->base) free(bpath->base);
	free(bpath);
}


int boxpath_getfile(boxpath * bpath)
{
    list_iter it;
    boxfile * aFile;

    /* check for obvious cases */
    if(!bpath) return FALSE;
    if(bpath->file) return TRUE;

    it = list_get_iter(bpath->is_dir ? bpath->dir->folders : bpath->dir->files);
    for(; it; it = list_iter_next(it)) {
        aFile = (boxfile*)list_iter_getval(it);
        if(!strcmp(aFile->name, bpath->base)) {
            bpath->file = aFile;
            return TRUE;
        }
    }
    return FALSE;

}

int boxpath_removefile(boxpath * bpath)
{
	if(!boxpath_getfile(bpath)) return FALSE;

        return list_delete_item(
                bpath->is_dir ? bpath->dir->folders : bpath->dir->files,
		bpath->file);

}

int boxpath_renamefile(boxpath * bpath, const char * name)
{
	if(!boxpath_getfile(bpath)) return FALSE;
    bpath->base = strdup(name);
    bpath->file->name = strdup(name);
}


int filename_comparator(void * p1, void * p2)
{
    boxfile * f1 = (boxfile *) p1, * f2 = (boxfile *) p2;
    return strcmp(f1->name, f2->name);
}

/* boxtree_setup and helpers
   used at mount time to fill the allDirs hash
*/

void parse_dir(const char * path, xmlNode * node, const char * id)
{
  xmlNodePtr cur_node, cur_file, cur_dir;
  xmlAttrPtr attrs;
  boxdir * aDir;
  boxfile * aFile;
  char * newPath;
  int plen = strlen(path);

  aDir = boxdir_create();

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
        if(options.splitfiles && ends_with(aFile->name, PART_SUFFIX)) {
            list_insert_sorted_comp(aDir->pieces, aFile, filename_comparator);
        } else {
            list_append(aDir->files,aFile);
        }
      }
      if(options.splitfiles) {
          //TODO: adjust sizes of files summing up all parts
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
        list_append(aDir->folders,aFile);

        newPath = (char *) malloc(plen + strlen(aFile->name) + 2);
        sprintf(newPath, (plen==1 ? "%s%s" : "%s/%s"), path, aFile->name);
        parse_dir(newPath, cur_dir, aFile->id);
        free(newPath);
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

  allDirs = xmlHashCreate(DIR_HASH_SIZE);
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

char * 	pathappend(const char * one, const char * two)
{
  char * res = malloc(strlen(one)+strlen(two)+2);
  res[0]=0;
  sprintf(res, "%s/%s", one, two);
  return res;
}

// Move a dir to another path in the tree,
// recursively updating all the child entries in allDirs
void	boxtree_movedir(const char * from, const char * to)
{
	boxdir * aDir = xmlHashLookup(allDirs, from);
        list_iter it;
        char * newfrom, * newto, *name;
	if(!aDir) {
	  syslog(LOG_ERR, "no such directory %s", from);
	  return;
	}
        for (it=list_get_iter(aDir->folders); it; it = list_iter_next(it)) {
            name = ((boxfile*)list_iter_getval(it))->name;
            newfrom = pathappend(from, name);
            newto   = pathappend(to,   name);
            boxtree_movedir(newfrom, newto);
            free(newfrom); free(newto);
        }
	//LOCKDIR(aDir);
	xmlHashRemoveEntry(allDirs, from, NULL);
	xmlHashAddEntry(allDirs, to, aDir);
	//UNLOCKDIR(aDir);
}
