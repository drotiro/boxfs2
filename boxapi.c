/***************************************

  DR: Interazione con il sito
  
  This software is licensed under the 
  GPLv3 license.

***************************************/

#include "boxapi.h"
#include "boxpath.h"
#include "boxhttp.h"
#include "boxopts.h"
#include "boxjson.h"
#include "boxutils.h"
#include "boxcache.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>
#include <curl/curl.h>

#include <libxml/hash.h>

#include <libapp/app.h>
/* Building blocks for OpenBox api endpoints
   and return codes
*/
// -- v2 --
//    AUTH
#define API_KEY_VAL "f9ss11y2w0hg5r04jsidxlhk4pil28cf"
#define API_SECRET  "r3ZHAIhsOL2FoHjgERI9xf74W5skIM0w"
#define API_OAUTH_URL "https://www.box.com/api/oauth2/"
#define API_OAUTH_AUTHORIZE API_OAUTH_URL "authorize?response_type=code&client_id=" API_KEY_VAL /*"&redirect_uri=http%3A//localhost"*/
#define API_OAUTH_TOKEN     API_OAUTH_URL "token"
//    CALLS
#define API_ENDPOINT	"https://api.box.com/2.0/"
#define API_LS		API_ENDPOINT "folders/"
#define API_FILES	API_ENDPOINT "files/%s"
#define API_INFO	API_ENDPOINT "users/me"
#define API_DOWNLOAD	API_FILES    "/content"
#define API_UPLOAD      "https://upload.box.com/api/2.0/files/content"
#define API_UPLOAD_VER  "https://upload.box.com/api/2.0/files/%s/content"
//    POST DATA
#define POST_CREATEDIR  "{\"name\":\"%s\", \"parent\": {\"id\": \"%s\"}}"
#define POST_RENAME     "{\"name\":\"%s\"}"
#define POST_MOVE       "{\"parent\": {\"id\": \"%s\"}}"
//    UTILS
#define BUFSIZE 1024

#define LOCKDIR(dir) pthread_mutex_lock(dir->dirmux);
#define UNLOCKDIR(dir) pthread_mutex_unlock(dir->dirmux); 

/* globals, written during initialization */
char *auth_token = NULL, *refresh_token = NULL;
long long tot_space, used_space;
struct box_options_t options;

int ends_with(const char * str, const char * suff)
{
        char * sub = strstr(str, suff);
        if(!sub) return FALSE;
        return !strcmp(suff, sub);
}


void api_free(int argc, char **argv)
{
	//api_logout();

	if(auth_token) free(auth_token);
	if(refresh_token) free(refresh_token);
	syslog(LOG_INFO, "Unmounting filesystem");
	closelog();
  
	xmlCleanupParser();
	curl_global_cleanup();
	if(argc>2) free(argv);
	if(allDirs) xmlHashFree(allDirs, NULL); // TODO: Deallocator!
}

/* APIv2 
 * Handle Oauth2 authentication
 */
void save_tokens(const char * token_file)
{
	FILE * tf = fopen(token_file, "w");
	
	if(tf) {
		fprintf(tf, "%s\n%s\n", auth_token, refresh_token);
		fclose(tf);
	}
}
 
int get_oauth_tokens()
{
	int res = 0;
	char * buf = NULL, * code = NULL;
	jobj * tokens;
	postdata_t postpar=post_init();

	printf("Visit %s to authorize, then paste the code below\n", API_OAUTH_AUTHORIZE);
	code = app_term_askpass("Code:");

	post_add(postpar, "grant_type", "authorization_code");
	post_add(postpar, "code", code);
	post_add(postpar, "client_id", API_KEY_VAL);
	post_add(postpar, "client_secret", API_SECRET);
	buf = http_post(API_OAUTH_TOKEN, postpar);

	tokens = jobj_parse(buf);
	if(tokens) {
		auth_token = jobj_getval(tokens, "access_token");
		refresh_token = jobj_getval(tokens, "refresh_token");
		if(auth_token) {
			if(options.verbose) syslog(LOG_DEBUG, "auth_token=%s - refresh_token=%s\n",
				auth_token, refresh_token);
			if(options.token_file) save_tokens(options.token_file);
		} else {
			char * err = jobj_getval(tokens, "error_description");
			fprintf(stderr, "Unable to get access token: %s\n", err ? err : "unknown error");
			if(err) free(err);
		}
		jobj_free(tokens);
	} else {
        	fprintf(stderr, "Unable to parse server response:\n%s\n", buf);
	}

	post_free(postpar);
	if(buf)    free(buf);
	if(code)   free(code);
	return res;
}

int refresh_oauth_tokens()
{
	int res = 0;
	char * buf = NULL;
	jobj * tokens;
	postdata_t postpar=post_init();

	post_add(postpar, "grant_type", "refresh_token");
	post_add(postpar, "refresh_token", refresh_token);
	post_add(postpar, "client_id", API_KEY_VAL);
	post_add(postpar, "client_secret", API_SECRET);
	buf = http_post(API_OAUTH_TOKEN, postpar);

	tokens = jobj_parse(buf);
	if(tokens) {
		auth_token = jobj_getval(tokens, "access_token");
		refresh_token = jobj_getval(tokens, "refresh_token");
		if(auth_token) {
			if(options.verbose) syslog(LOG_DEBUG, "auth_token=%s - refresh_token=%s\n",
				auth_token, refresh_token);
			if(options.token_file) save_tokens(options.token_file);
		} else {
			char * err = jobj_getval(tokens, "error_description");
			syslog(LOG_ERR, "Unable to get access token: %s\n", err ? err : "unknown error");
			res = 1;
			if(err) free(err);
		}
		jobj_free(tokens);
	} else {
        	fprintf(stderr, "Unable to parse server response:\n%s\n", buf);
	}

	post_free(postpar);
	if(buf) free(buf);
	return res;
}

jobj * get_account_info() {
	char * buf = NULL;
	jobj * o;

	buf = http_fetch(API_INFO);
	o = jobj_parse(buf);
	free(buf);
	
	return o;
}

void api_getusage(long long * tot_sp, long long * used_sp)
{
  *tot_sp = tot_space;
  *used_sp = used_space;
}

int api_createdir(const char * path)
{
	int res = 0;
	boxpath * bpath;
	boxdir *newdir;
	boxfile * aFile;
	char * dirid = NULL, *buf = NULL;
	jobj * folder = NULL;
	char fields[BUFSIZE]="";

	bpath = boxpath_from_string(path);
	if(bpath->dir) {
		snprintf(fields, BUFSIZE, POST_CREATEDIR,
		        bpath->base, bpath->dir->id);

		buf = http_post_fields(API_LS, fields);

		if(buf) { 
			folder = jobj_parse(buf); 
			free(buf);
		}
		if(folder) {
		        dirid = jobj_getval(folder, "id");
        		free(folder);
                }

		if(!dirid) {
			res = -EINVAL;
			boxpath_free(bpath);
			return res;
		}

		// add 1 entry to the hash table
		newdir = boxdir_create();
		newdir->id = dirid;
		xmlHashAddEntry(allDirs, path, newdir);
		// upd parent
		aFile = boxfile_create(bpath->base);
		aFile->id = strdup(dirid);
		LOCKDIR(bpath->dir);
		list_append(bpath->dir->folders, aFile);
		UNLOCKDIR(bpath->dir);    
		// invalidate cached parent entry
		cache_rm(bpath->dir->id);
	} else {
		syslog(LOG_WARNING, "UH oh... wrong path %s",path);
		res = -EINVAL;
	}
	boxpath_free(bpath);

	return res;
}


int api_create(const char * path)
{
  int res = 0;
  boxpath * bpath = boxpath_from_string(path);
  boxfile * aFile;

  if(bpath->dir) {
    aFile = boxfile_create(bpath->base);
    LOCKDIR(bpath->dir);
    list_append(bpath->dir->files,aFile);
    UNLOCKDIR(bpath->dir);
  } else {
    syslog(LOG_WARNING, "UH oh... wrong path %s",path);
    res = -ENOTDIR;
  }
  boxpath_free(bpath);
  
  return res;
}

char * get_folder_info_next(const char * id, int offset )
{
        char * buf = NULL;
        buf = http_fetchf(API_LS "%s/items?fields=size,name,created_at,modified_at&offset=%d&limit=1000", id, offset);
	return buf;
}

char * get_folder_info(const char * id, int items )
{
	char * buf = NULL;
	
	if(items) {
		buf = cache_get(id);
		if(buf) return buf;
		buf = http_fetchf(API_LS "%s/items?fields=size,name,created_at,modified_at&limit=1000", id);
		cache_put(id, buf);
		return buf;
	}
	
	return http_fetchf(API_LS "%s", id);
}

void set_filedata(const boxpath * bpath, char * res, long long fsize)
{
        boxfile * aFile;
        list_iter it = list_get_iter(bpath->dir->files);
        jobj * o = jobj_parse(res);
        
        if(!o) {
                syslog(LOG_ERR, "Unable to parse file data for %s", bpath->base);
                return;
        }
        o = jobj_get(o, "entries");
        if(!o || o->type != T_ARR) {
                syslog(LOG_ERR, "Unable to parse json data for %s", bpath->base);
                return;
        } 

        o = jobj_array_item(o, 0); //first item
        for(; it; it = list_iter_next(it)) {
                aFile = (boxfile*)list_iter_getval(it);
                if(!strcmp(aFile->name, bpath->base)) {
                        aFile->id = jobj_getval(o, "id");
                        aFile->size = fsize;
                        return;
		}
	}
}

void set_partdata(const boxpath * bpath, char * res, const char * partname)
{
	boxfile * aFile;
	jobj * o = jobj_parse(res);

        if(!o) {
                syslog(LOG_ERR, "Unable to parse file data for %s", bpath->base);
                return;
        }
        o = jobj_get(o, "entries");
        if(!o || o->type != T_ARR) {
                syslog(LOG_ERR, "Unable to parse json data for %s", bpath->base);
                return;
        } 
        
        o = jobj_array_item(o, 0); //first item
        aFile = boxfile_create(partname);
        aFile->id=jobj_getval(o, "id");
        LOCKDIR(bpath->dir);
        list_append(bpath->dir->pieces, aFile);
        UNLOCKDIR(bpath->dir);
}


int api_open(const char * path, const char * pfile){
	int res = 0;
	char url[BUFSIZE]="";
	boxfile * aFile;
	list_iter it;
	boxpath * bpath = boxpath_from_string(path);

	if(!boxpath_getfile(bpath)) {
                if(options.verbose) syslog(LOG_DEBUG, "Can't find path %s",
                        path);	        
	        res = -ENOENT;
        }
        if(!res && !bpath->file->id) {
                if(options.verbose) syslog(LOG_DEBUG, "Missing file id for %s",
                        path);	        
	        res = -ENOENT;
        }

	if(!res) {
		sprintf(url, API_DOWNLOAD, bpath->file->id);
		res = http_fetch_file(url, pfile, FALSE);
		//NOTE: we could check for bpath->file->size > PART_LEN, but
		//checking filesize is more robust, since PART_LEN may change in
		//future, or become configurable.
		if(!res && options.splitfiles && bpath->file->size > filesize(pfile)) {
			//download of other parts
			for(it = boxpath_first_part(bpath); it ; it=boxpath_next_part(bpath, it)) {
				aFile = (boxfile*) list_iter_getval(it);
				snprintf(url, BUFSIZE, API_DOWNLOAD, aFile->id);
				if(options.verbose) syslog(LOG_DEBUG, "Appending file part %s", aFile->name);
				http_fetch_file(url, pfile, TRUE);
			}
		}
	}
  
	boxpath_free(bpath);  
	return res;
}

int api_readdir(const char * path, fuse_fill_dir_t filler, void * buf)
{
  int res = 0;
  boxdir * dir;
  boxfile * aFile;
  list_iter it;
  
  dir = (boxdir *) xmlHashLookup(allDirs,path);
  if (dir==NULL) return -EINVAL;

  filler(buf, ".", NULL, 0);
  filler(buf, "..", NULL, 0);

  LOCKDIR(dir);
  for(it=list_get_iter(dir->folders); it; it = list_iter_next(it)) {
      aFile = (boxfile*)list_iter_getval(it);
      filler(buf, aFile->name, NULL, 0);
  }
  for(it=list_get_iter(dir->files); it; it = list_iter_next(it)) {
      aFile = (boxfile*)list_iter_getval(it);
      filler(buf, aFile->name, NULL, 0);
  }
  UNLOCKDIR(dir);

  return res;
}

int api_subdirs(const char * path)
{
  boxdir * dir;
  
  dir = (boxdir *) xmlHashLookup(allDirs,path);
  if (dir==NULL) return -1;

  return list_size(dir->folders);
}  

int api_getattr(const char *path, struct stat *stbuf)
{
	memset(stbuf, 0, sizeof(struct stat));	
	boxpath * bpath = boxpath_from_string(path);
	if(!bpath) return -ENOENT;
	if(!boxpath_getfile(bpath)) {
		boxpath_free(bpath);
		return -ENOENT;
	}
	stbuf->st_size = bpath->file->size;
	stbuf->st_ctime = bpath->file->ctime;
	stbuf->st_mtime = bpath->file->mtime;
	// access time unknown, approx with mtime
	stbuf->st_atime = bpath->file->mtime;
	stbuf->st_uid = options.uid;
	stbuf->st_gid = options.gid;
	if(bpath->is_dir) {
		stbuf->st_mode = S_IFDIR | options.dperm;
		stbuf->st_nlink = 2 + api_subdirs(path);
	} else {
		stbuf->st_mode = S_IFREG | options.fperm;
		stbuf->st_nlink = 1;
	}
	boxpath_free(bpath);
	return 0;
}

int api_removedir(const char * path)
{
	int res = 0;
	char url[BUFSIZE]="";
	long sc;
	boxpath * bpath = boxpath_from_string(path);
	if(!bpath) return -EINVAL;

	/* check that is a dir */
	if(!boxpath_getfile(bpath)) {
		free(bpath);
		return -EINVAL;
	}
	if(!bpath->dir || !bpath->is_dir) {
		free(bpath);
		return -ENOENT;
	}

	snprintf(url, BUFSIZE, API_LS "%s", bpath->file->id);
	sc = http_delete(url);

	if(sc != 204) res = -EPERM;

	if(!res) {
		//remove it from parent's subdirs...
		LOCKDIR(bpath->dir);
		boxpath_removefile(bpath);
		UNLOCKDIR(bpath->dir);
		//...and from dir list
		xmlHashRemoveEntry(allDirs, path, NULL);
		// invalidate parent cache entry
		cache_rm(bpath->dir->id);
	}

	boxpath_free(bpath);  
	return res;
}

/*
 * Internal func to call the delete api on a file id.
 * api_removefile will call it several times if
 * splitfiles is on and the file has parts
 */
int do_removefile_id(const char * id)
{
	int res = 0;
	long sc;
	char url[BUFSIZE]="";
	
	snprintf(url, BUFSIZE, API_FILES, id);
	sc = http_delete(url);
	if(sc != 204) res = -ENOENT;
	
	return res;
}

int api_removefile(const char * path)
{
	int res = 0;
	boxpath * bpath = boxpath_from_string(path);

	if(!bpath->dir) res = -ENOENT;
	else {
		//remove it from box.com
		if(!boxpath_getfile(bpath)) res = -ENOENT;
		else res = do_removefile_id(bpath->file->id);

		if(res==0) {
        		used_space -= bpath->file->size;

			if(options.splitfiles && list_size(bpath->dir->pieces)) {
				list_iter cur;
				boxfile * part;

				//remove parts
				for(cur = boxpath_first_part(bpath); cur; ) {
					part = (boxfile*) list_iter_getval(cur);
					if (options.verbose) syslog(LOG_DEBUG, "removing part %s", part->name);
					do_removefile_id(part->id);
					cur = boxpath_next_part(bpath, cur);
					list_delete_item(bpath->dir->pieces, part);
				}
			}

			//remove it from the list
			LOCKDIR(bpath->dir);
			boxpath_removefile(bpath);
			UNLOCKDIR(bpath->dir);
			//invalidate cache entry
			cache_rm(bpath->dir->id);
		}
	}
	
	boxpath_free(bpath);
	return res;
}

/*
 * Move and rename funcs, new version
 */

//predeclaration
int do_api_move_id(int is_dir, const char * id, const char * dest, int is_rename);

int do_api_move(boxpath * bsrc, boxpath * bdst)
{
	int res = 0;
	list_iter it;

	LOCKDIR(bsrc->dir);
	res = do_api_move_id(bsrc->is_dir, bsrc->file->id, bdst->dir->id, FALSE);
	if(!res) {
		boxfile * part;
		//take care of parts, if any
		if(options.splitfiles && !bsrc->is_dir && list_size(bsrc->dir->pieces))
			for(it = boxpath_first_part(bsrc); it; it = boxpath_next_part(bsrc, it)) {
				part = (boxfile*)list_iter_getval(it);
				if(options.verbose) syslog(LOG_DEBUG, "Moving part %s", part->name);
				do_api_move_id(FALSE, part->id, bdst->dir->id, FALSE);
				list_insert_sorted_comp(bdst->dir->pieces, part, filename_compare);
				list_delete_item(bsrc->dir->pieces, part);				
			}
		
		boxpath_removefile(bsrc);
		LOCKDIR(bdst->dir);
		list_append((bsrc->is_dir ? bdst->dir->folders : bdst->dir->files),
			bsrc->file);
		UNLOCKDIR(bdst->dir);
	}
	UNLOCKDIR(bsrc->dir);
	
	return res;
}

int do_api_move_id(int is_dir, const char * id, const char * dest, int is_rename)
{
        char url[BUFSIZE], fields[BUFSIZE], * buf, * type;
        int res = 0;
        jobj * obj;
        
        if(is_dir) {
                snprintf(url, BUFSIZE, API_LS "%s", id);
        } else {
                snprintf(url, BUFSIZE, API_FILES, id);
        }
        if(is_rename) {
		snprintf(fields, BUFSIZE, POST_RENAME, dest);
	} else {
		snprintf(fields, BUFSIZE, POST_MOVE, dest);
	}

	buf = http_put_fields(url, fields);
	obj = jobj_parse(buf);
	type = jobj_getval(obj, "type");
	if(!type)
		res = -EINVAL;
	else
		if(strcmp(type, is_dir ? "folder" : "file")) res = -EINVAL;

        if(type) free(type);
        free(buf);
        jobj_free(obj);
        return res;
}

int do_api_rename(boxpath * bsrc, boxpath * bdst)
{
	int res;
	
	LOCKDIR(bsrc->dir);
	res = do_api_move_id(bsrc->is_dir, bsrc->file->id, bdst->base, TRUE);
	if(!res) {
		boxfile * part;
		char * newname;
		list_iter it;
		int ind=1;
		//take care of parts, if any
		if(options.splitfiles && !bsrc->is_dir && list_size(bsrc->dir->pieces))
			for(it = boxpath_first_part(bsrc); it; ) {
				part = (boxfile*)list_iter_getval(it);
				newname = malloc(strlen(bdst->base)+ PART_SUFFIX_LEN +4);
				sprintf(newname, "%s.%.2d" PART_SUFFIX, bdst->base, ind++);
				if(options.verbose) syslog(LOG_DEBUG, "Renaming part %s to %s", part->name, newname);
				do_api_move_id(FALSE, part->id, newname, TRUE);
				it = boxpath_next_part(bsrc, it);
				list_delete_item(bsrc->dir->pieces, part);
				part->name = newname;
				list_insert_sorted_comp(bsrc->dir->pieces, part, filename_compare);
			}

		boxpath_renamefile(bsrc, bdst->base);
	}
	UNLOCKDIR(bsrc->dir);

	return res;
}

int api_rename_v2(const char * from, const char * to)
{
	int res = 0;
	boxpath * bsrc = boxpath_from_string(from);
	boxpath * bdst = boxpath_from_string(to);
	if(!boxpath_getfile(bsrc)) {
	        boxpath_free(bsrc);
	        boxpath_free(bdst);
	        return -EINVAL; 
        }
	//no more needed
	//boxpath_getfile(bdst);

	if(bsrc->dir!=bdst->dir) {
		res=do_api_move(bsrc, bdst);
	}
	if(!res && strcmp(bsrc->base, bdst->base)) {
		res = do_api_rename(bsrc,bdst);
	}
	if(!res && bsrc->is_dir) {
	    boxtree_movedir(from, to);
	}

	// invalidate cache entries
	cache_rm(bsrc->dir->id);
	if(bsrc->dir!=bdst->dir) cache_rm(bdst->dir->id);
	boxpath_free(bsrc);
	boxpath_free(bdst);
	return res;
}

void api_upload(const char * path, const char * tmpfile)
{
  postdata_t buf = post_init();
  char * res = NULL, * pr = NULL, * partname="";
  off_t fsize, oldsize = 0;
  size_t start, len;
  int oldver;

  boxpath * bpath = boxpath_from_string(path);

  if(bpath->dir) {
    post_add(buf, "parent_id", bpath->dir->id);
    fsize = filesize(tmpfile);
    oldver = (boxpath_getfile(bpath) && bpath->file->size);
    if(oldver) oldsize = bpath->file->size;
    
    //if there was an older version of the file with parts, remove them
    if(options.splitfiles && oldver && (oldsize > PART_LEN)) {
    	api_removefile(path);
    }
    //upload file in parts if needed
    if(options.splitfiles && fsize > PART_LEN) {
        pr = post_addfile_part(buf, bpath->base, tmpfile, 0, PART_LEN);
        res = http_postfile(API_UPLOAD, buf);

        set_filedata(bpath ,res, fsize);
        free(res); if(pr) free(pr);

        start = PART_LEN;
        while(start < fsize-1) {
	    post_free(buf); buf = post_init();
            post_add(buf, "parent_id", bpath->dir->id);
            
            partname = (char*) malloc(strlen(bpath->base)+PART_SUFFIX_LEN+4);
            sprintf(partname, "%s.%.2d%s", bpath->base, (int)(start/PART_LEN), PART_SUFFIX);

            if(options.verbose) syslog(LOG_DEBUG, "Uploading file part %s", partname);
            len = MIN(PART_LEN, fsize-start);
            pr = post_addfile_part(buf, partname, tmpfile, start, len);
            res = http_postfile(API_UPLOAD, buf);
            set_partdata(bpath, res, partname);

            if(pr) free(pr); free(res); free(partname);
            start += len;
        }
    } else if(fsize) {
    	//normal upload
    	post_addfile(buf, bpath->base, tmpfile);
    	if(oldver) {
    	        char url[BUFSIZE]="";
    	        snprintf(url, BUFSIZE, API_UPLOAD_VER, bpath->file->id);
    	        res = http_postfile(url, buf);
        } else {
                res = http_postfile(API_UPLOAD, buf);
        }

	set_filedata(bpath ,res, fsize);
	free(res);
    }

    // update used space and invalidate cache
    used_space = used_space - oldsize + fsize;
    cache_rm(bpath->dir->id);
    
  } else {
    syslog(LOG_ERR,"Couldn't upload file %s",bpath->base);
  }
  post_free(buf);
  boxpath_free(bpath);
}

void do_add_folder(const char * path, const char * id)
{
	char * buf;
	jobj * obj;
	boxdir * dir;
	boxfile * f;
	list_iter it;
	
	buf = get_folder_info(id, true);
	obj = jobj_parse(buf);
	free(buf);
	
	if(obj) {
	        long long tot_count = jobj_getlong(obj, "total_count"), offset = 1000;
	        list * objs = list_new_full((list_deallocator)jobj_free);
	        list_append(objs, obj);
                
                while (tot_count > offset) {
                        buf = get_folder_info_next(id, offset);
                        obj = jobj_parse(buf);
                        free(buf);
                        list_append(objs, obj);
                        offset+=1000;
                }

	  	dir = boxtree_add_folder(path, id, objs);
	  	list_free(objs);
	  	it = list_get_iter(dir->folders);
	  	for(; it; it = list_iter_next(it)) {
	  	        f = list_iter_getval(it);
	  	        buf = pathappend(path, f->name);
	  		do_add_folder(buf, f->id);
	  		free(buf);
	  	}
	}
}


/*
 * Helper threads
 */
void * refresher_thread(void * unused)
{
        if(options.verbose) syslog(LOG_DEBUG, "Token-refresh thread started");
        do {
                sleep(1800);
                refresh_oauth_tokens();
        	update_auth_header(auth_token);
        } while(TRUE);
}

void start_helper_threads()
{
        pthread_t rt;
        if(pthread_create(&rt, NULL, refresher_thread, NULL)) {
                syslog(LOG_WARNING, "Can't create token-refresh thread");
        }

}

/*
 * Login to box.net, get the auth_token
 */
int api_init(int* argc, char*** argv) {

	int res = 0;

	/* parse command line arguments */
	if (parse_options (argc, argv, &options))
		return 1;  
  
	curl_global_init(CURL_GLOBAL_DEFAULT);
	xmlInitParser();
	openlog("boxfs", LOG_PID, LOG_USER);
	cache_init(options.cache_dir, options.expire_time);

	if(!auth_token || !refresh_token) 
  		res = get_oauth_tokens();
        else {
        	res = refresh_oauth_tokens();
        	/* if refresh_token expires, redo auth */
        	if(res) res = get_oauth_tokens();
        }
        
  	if(auth_token) {  	        
  		char * buf;
  		jobj * root, *info;
  		
  		// must be done this way because
  		//fuse forks a new process
  		pthread_atfork(NULL, NULL, start_helper_threads);
  		
        	update_auth_header(auth_token);
        	set_conn_reuse(TRUE);
        	buf = get_folder_info("0", false);
        	info = get_account_info();
        	root = jobj_parse(buf);
        	tot_space = jobj_getlong(info, "space_amount");
        	used_space = jobj_getlong(info, "space_used");
  		boxtree_init(root, info);
  		jobj_free(root); jobj_free(info);
  		free(buf);

  		do_add_folder("/", "0");
  		set_conn_reuse(FALSE);

  		syslog(LOG_INFO, "Filesystem mounted on %s", options.mountpoint);
	}
	curl_global_cleanup();
  
	return res;
}

