/*************************************

  DR: Local file-tree representation
      data structures and functions

  This software is licensed under the 
  GPLv2 license.

*************************************/

#include "boxpath.h"
#include "boxapi.h"
#include "boxopts.h"
#include "boxutils.h"

#include <string.h>
#include <libgen.h>
#include <errno.h>
#include <syslog.h>
#include <time.h>

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
    return TRUE;
}

list_iter   boxpath_first_part(boxpath * bpath)
{
	list_iter it;
	boxfile * part;
	if(!boxpath_getfile(bpath)) return NULL;
	
	it = list_get_iter(bpath->dir->pieces);
	while(it && (filename_compare(bpath->file, list_iter_getval(it)) > 0))
		it = list_iter_next(it);
	if(it) {
		part = (boxfile*) list_iter_getval(it);
		if(strncmp(bpath->base, part->name, strlen(bpath->base)))
			return NULL;
	}
	
	return it;
}

list_iter   boxpath_next_part(boxpath * bpath, list_iter it)
{
	boxfile * part;
	
	it = list_iter_next(it);
	if(it) {
		part = (boxfile*) list_iter_getval(it);
		if(strncmp(bpath->file->name, part->name, strlen(bpath->file->name)))
			return NULL;
	}

	return it;	
}

/* boxtree_* functions and helpers
   used at mount time to fill the allDirs hash
*/
void find_file_for_part(const char * pname, list_iter * it)
{
    boxfile  * f;
    while(*it) {
        f = (boxfile*) list_iter_getval(*it);
        if(!strncmp(f->name, pname, strlen(f->name))) break;
        *it = list_iter_next(*it);
    }
}

int filename_compare(void * p1, void * p2)
{
    boxfile * f1 = (boxfile *) p1, * f2 = (boxfile *) p2;
    return strcmp(f1->name, f2->name);
}

void setup_root_dir(jobj * root, jobj * info)
{
	rootDir = (boxfile*) malloc(sizeof(boxfile));
	rootDir->size = 0;
	rootDir->name = strdup("/");
	rootDir->size = jobj_getlong(root, "size");
	rootDir->ctime = jobj_gettime(info, "created_at");
	rootDir->mtime = jobj_gettime(info, "modified_at");
/*
	xmlAttrPtr attrs;

	rootDir = (boxfile*) malloc(sizeof(boxfile));
	rootDir->size = 0;
	rootDir->name = strdup("/");
	for (attrs = cur_node->properties; attrs; attrs = attrs->next) {
		if(!strcmp(attrs->name,"created")) rootDir->ctime = atol(attrs->children->content);
		else if(!strcmp(attrs->name,"updated")) rootDir->mtime = atol(attrs->children->content);
		else if(!strcmp(attrs->name,"size")) rootDir->size = atol(attrs->children->content);
	}
*/
}

boxfile * obj_to_file(jobj * obj)
{
	list_iter it;
	jobj * item;
	boxfile * f = (boxfile*) malloc(sizeof(boxfile));
	
	memset(f, 0, sizeof(boxfile));
	it = list_get_iter(obj->children);
	for(; it; it = list_iter_next(it)) {
		item = list_iter_getval(it);
		if(!strcmp(item->key,"id")) f->id = strdup(item->value);
		else if(!strcmp(item->key, "size")) f->size = atoll(item->value);
		else if(!strcmp(item->key, "name")) f->name = strdup(item->value);
		else if(!strcmp(item->key, "created_at")) f->ctime = unix_time(item->value);
		else if(!strcmp(item->key, "modified_at")) f->mtime = unix_time(item->value);
	}

	return f;
}

boxdir * boxtree_add_folder(const char * path, const char * id, jobj * folder)
{
	boxdir * aDir;
	boxfile * aFile, * part;
	list_iter it, pit;
	jobj * obj, *item;
	char * type;

	aDir = boxdir_create();
	aDir->id = strdup(id);
	
	syslog(LOG_DEBUG, "Adding %s", path);
	obj = jobj_get(folder, "entries");
	it = list_get_iter(obj->children);
	for(; it; it = list_iter_next(it)) {
        	item = list_iter_getval(it);
		aFile = obj_to_file(item);

        	type = jobj_getval(item, "type");
        	if(!strcmp(type,"folder")) list_append(aDir->folders, aFile);
        	else list_append(aDir->files, aFile);
        	free(type);
	}
	
	xmlHashAddEntry(allDirs, path, aDir);
	return aDir;
	
/*
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
            list_insert_sorted_comp(aDir->pieces, aFile, filename_compare);
        } else {
            list_append(aDir->files,aFile);
        }
      }
      if(options.splitfiles) {
        it = list_get_iter(aDir->files);
        pit = list_get_iter(aDir->pieces);
        for(; pit; pit = list_iter_next(pit)) {
            part = (boxfile*)list_iter_getval(pit);
            find_file_for_part(part->name, &it);
            if(it) {
                aFile = (boxfile*)list_iter_getval(it);
                aFile->size+=part->size;
            } else {
                syslog(LOG_WARNING, "Stale file part %s found", part->name );
                it = list_get_iter(aDir->files);
            }
        }
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
      }
    }
    //skipping tags & sharing info 
  }
*/
}

void boxtree_init(jobj * root, jobj * info)
{
	setup_root_dir(root, info);
	allDirs = xmlHashCreate(DIR_HASH_SIZE);	
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
