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

/* boxtree_setup and helpers
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

void parse_dir(const char * path, xmlNode * node, const char * id)
{
  xmlNodePtr cur_node, cur_file, cur_dir;
  xmlAttrPtr attrs;
  boxdir * aDir;
  boxfile * aFile, * part;
  char * newPath;
  int plen = strlen(path);
  list_iter it, pit;

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

/*
 * Helpers for base64 and deflate decoding
 * base64 decoder adapted from a PD implementation
 * found on the net.
 */
char b64chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

inline char decode(char q)
{
        return strchr(b64chars, q) - b64chars;
}

int base64_decode(char *src, char * dst)
{
  int x, y = 0;
  int len;
  char triple[3];
  char quad[4];

  len = strlen(src);
  if(src[len-2]=='=') src[len-2]='A';
  if(src[len-1]=='=') src[len-1]='A';
  for(x = 0; x < len; x += 4)
    {
          while(src[x]=='\r' || src[x]=='\n') ++x; //skip eol
      memset(quad, 0, 4);
      memcpy(quad, &src[x], (len - x) >= 4 ? 4 : len - x );

      quad[0] = decode(quad[0]);
      quad[1] = decode(quad[1]);
      quad[2] = decode(quad[2]);
      quad[3] = decode(quad[3]);
      triple[0] = (quad[0] << 2) | quad[1] >> 4;
      triple[1] = ((quad[1] << 4) & 0xF0) | quad[2] >> 2;
      triple[2] = ((quad[2] << 6) & 0xC0) | quad[3];
      memcpy(&dst[y], triple, 3);
      y += 3;
    }

  return y;
}

int unzip_first(const char * fname, char * dest)
{
    struct zip * z;
    struct zip_file * zf;
    char buf[16384], *dp = dest;
    int br;

    z = (struct zip *) zip_open(fname, 0, NULL);
    zf = (struct zip_file *) zip_fopen_index(z, 0, 0);
    while(br = zip_fread(zf, buf, sizeof(buf)))
    {
        memcpy(dp, buf, br);
        dp+=br;
    }
    zip_fclose(zf);
    zip_close(z);
    *dp=0;
    return (dp-dest);
}
/*   */

void boxtree_setup(const char * treefile)
{
  xmlDoc *doc = NULL;
  xmlNode *root_element = NULL;
  xmlNode *cur_node = NULL;
  char * tree_decoded, * tree_encoded, * tree_xml;
  long tlen, zlen, zres;
  FILE * tf;

  allDirs = xmlHashCreate(DIR_HASH_SIZE);
  doc = xmlParseFile(treefile);
  root_element = xmlDocGetRootElement(doc);
  /* 
   * let's go to /response/tree node
   * it's a base64 encoded ziparchive
   */
  cur_node = root_element->children;
  while(strcmp(cur_node->name,"tree")) cur_node = cur_node->next; //skip status
  tree_encoded = cur_node->children->content;
  tree_decoded = malloc(strlen(tree_encoded)+1);
  zlen = base64_decode(tree_encoded, tree_decoded);
  xmlFreeDoc(doc);
  //save the zip 'cause zip_open wants a file
  tf = fopen(treefile, "w");
  fwrite(tree_decoded, 1, zlen, tf);
  fclose(tf);
  free(tree_decoded);
  //unzip the tree to memory
  tlen = zlen*15;
  tree_xml = malloc(tlen);
  unzip_first(treefile, tree_xml);
  doc = xmlParseDoc(tree_xml);
  cur_node = xmlDocGetRootElement(doc);
  setup_root_dir(cur_node);
  parse_dir("/",cur_node,"0");

  xmlFreeDoc(doc);
  free(tree_xml);
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
