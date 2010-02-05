/***************************************

  DR: Interazione con il sito
  
  This software is licensed under the 
  GPLv2 license.

***************************************/

#include "boxapi.h"
#include "boxpath.h"
#include "boxhttp.h"
#include "boxopts.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <termios.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <sys/stat.h>

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/uri.h>

/* Some constant and utility define */
#define BOX_ERR(MSG) fprintf(stderr,MSG)
#define FALSE 0
#define TRUE  1
#define PROTO_HTTP  "http"
#define PROTO_HTTPS "https"

/* Building blocks for OpenBox api endpoints
   and return codes
*/
#define API_KEY_VAL "2uc9ec1gtlyaszba4h6nixt7gyzq3xir"
#define API_KEY "&api_key=" API_KEY_VAL
#define API_TOKEN API_KEY "&auth_token="
#define API_REST_BASE "://www.box.net/api/1.0/rest?action="
#define API_GET_TICKET API_REST_BASE "get_ticket" API_KEY
#define API_GET_TICKET_OK "get_ticket_ok"
#define API_LOGIN_URL "https://www.box.net/api/1.0/auth/"
#define API_GET_AUTH_TOKEN API_REST_BASE "get_auth_token" API_KEY
#define API_GET_AUTH_TOKEN_OK "get_auth_token_ok"
#define API_GET_ACCOUNT_TREE API_REST_BASE "get_account_tree&params%%5B%%5D=nozip&folder_id=0" \
        API_TOKEN
#define API_GET_ACCOUNT_TREE_OK "listing_ok"
#define API_DOWNLOAD "://www.box.net/api/1.0/download/"
#define API_UPLOAD "://upload.box.net/api/1.0/upload/"
#define API_CREATE_DIR API_REST_BASE "create_folder" API_TOKEN
#define API_CREATE_DIR_OK "create_ok"
#define API_RENAME API_REST_BASE "rename" API_TOKEN
#define API_RENAME_OK "s_rename_node"
#define API_MOVE API_REST_BASE "move" API_TOKEN
#define API_MOVE_OK "s_move_node"
#define API_UNLINK API_REST_BASE "delete&target=file" API_TOKEN
#define API_UNLINK_OK "s_delete_node"
#define API_RMDIR API_REST_BASE "delete&target=folder" API_TOKEN
#define API_RMDIR_OK API_UNLINK_OK 
#define API_LOGOUT API_REST_BASE "logout" API_KEY "&auth_token="

#define LOCKDIR(dir) /*syslog(LOG_INFO, "LOCKING DIR %s", dir->id);*/ pthread_mutex_lock(dir->dirmux);
#define UNLOCKDIR(dir) pthread_mutex_unlock(dir->dirmux); /*syslog(LOG_INFO, "UNLOCKING DIR %s", dir->id);*/

/* globals, written during initialization */
char *ticket = NULL, *auth_token = NULL;
char treefile[] = "/tmp/boxXXXXXX";
long tot_space, used_space;
struct box_options_t options;
char * proto = PROTO_HTTP;

off_t filesize(const char * localpath)
{
  struct stat sb;
  
  stat(localpath, &sb);
  return sb.st_size;
}

char * tag_value(const char * buf, const char * tag)
{
  char * tmp;
  char * sp, * ep;
  
  sp = strstr(buf,tag)+strlen(tag)+1;
  ep = strstr(sp,"<");
  tmp =malloc(ep-sp+1);
  strncpy(tmp, sp, ep-sp);
  tmp[ep-sp]=0;
  
  return tmp;
}


long tag_lvalue(const char * buf, const char * tag)
{
  char * tmp;
  long rv;
  
  tmp = tag_value(buf, tag);
  rv = atol(tmp);
  free(tmp);
  
  return rv;  
}

char * attr_value(const char * buf, const char * attr)
{
  char * tmp;
  char * sp, * ep;
  char ss[24];

  sprintf(ss,"%s=\"", attr);
  sp = strstr(buf,ss);// +strlen(ss);
  if(!sp) return NULL;
  else sp = sp + strlen(ss);
  ep = strstr(sp,"\"");
  tmp =malloc(ep-sp+1);
  strncpy(tmp, sp, ep-sp);
  tmp[ep-sp]=0;

  return tmp;
}


void api_logout()
{
  char * buf;
  char gkurl[512];
  
  sprintf(gkurl,"%s" API_LOGOUT "%s", proto, auth_token);
  buf = http_fetch(gkurl);
  free(buf);
}

void api_free()
{

  api_logout();

  if(ticket) free(ticket);
  if(auth_token) free(auth_token);
  syslog(LOG_INFO, "Unmounting filesystem");
  closelog();
  
  xmlCleanupParser();
  if(allDirs) xmlHashFree(allDirs, NULL); // TODO: Deallocator!
}

/* only for 1st level nodes! */
char * node_value(const char * buf, const char * name)
{

  char * val = NULL;
  
  xmlDoc *doc = NULL;
  xmlNode *root_element = NULL;
  xmlNode *cur_node = NULL;
  
  doc = xmlReadDoc(buf, "noname.xml",NULL, 0);

  root_element = xmlDocGetRootElement(doc);

  for(cur_node = root_element->children; cur_node && !val; cur_node = cur_node->next) {
      if (cur_node->type == XML_ELEMENT_NODE) {
        if(!strcmp(name,cur_node->name)) { 
          // a nice thing of text nodes :(((
          val = (cur_node->content ? strdup(cur_node->content) : 
                            strdup(cur_node->children->content)); 
        }
      }
  }
  
  xmlFreeDoc(doc);
   
  return val;   
}

void set_echo(int enable)
{
  struct termios tio;
  int tty = fileno(stdin); //a better way?
  
  if(!tcgetattr(tty, &tio)) {
    if (enable) tio.c_lflag |= ECHO;
    else tio.c_lflag &= ~ECHO;
	
    tcsetattr(tty, TCSANOW, &tio);
  }
}

char * askuser(const char * what, int passwd)
{
  char * val = malloc(512);
  printf("%s ",what);
  if(passwd) set_echo(FALSE);
  scanf("%s",val);
  if(passwd) { set_echo(TRUE); printf("\n");}
  return val;
}

int get_ticket(struct box_options_t* options) {
  char * buf = NULL;
  char * status = NULL;
  int res = 0;
  postdata_t postpar=post_init();
  char gkurl[512];
  char* value;
  
  sprintf(gkurl, "%s" API_GET_TICKET, proto);
  buf = http_fetch(gkurl);
  gkurl[0] = 0;
  status = node_value(buf,"status");
  if(strcmp(status,API_GET_TICKET_OK)) {
    res = 1;
  }
  if(!res) ticket = node_value(buf,"ticket");
  
  if(buf) free(buf);
  if(status) free(status);

  /* autologin using http POST */
  post_add(postpar,"dologin","1");
  post_add(postpar,"__login","1");

  if (options->user)
      post_add(postpar,"login",options->user);
  else {
      value = askuser("Login: ",FALSE);
      post_add(postpar,"login",value);
      free (value);
  }

  if (options->password)
      post_add(postpar,"password",options->password);
  else {
      value = askuser("Password: ",TRUE);
      post_add(postpar,"password",value);
      free (value);
  }

  sprintf(gkurl, API_LOGIN_URL "%s",ticket);
  http_post(gkurl,postpar);
  post_free(postpar);
  
  return res;
}

void api_getusage(long * tot_sp, long * used_sp)
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
  char * dirid, *buf, *status;
  char gkurl[512];
  time_t now = time(NULL);

  bpath = boxpath_from_string(path);
  if(bpath->dir) {
	//syslog(LOG_WARNING, "creating dir %s (escaped: %s) ",base,xmlURIEscapeStr(base,""));
    sprintf(gkurl,"%s" API_CREATE_DIR "%s&parent_id=%s&name=%s&share=0", 
          proto, auth_token, bpath->dir->id, xmlURIEscapeStr(bpath->base,""));
    buf = http_fetch(gkurl);
    status = node_value(buf,"status");
    if(strcmp(status,API_CREATE_DIR_OK)) {
      res = -EINVAL;
      free(buf); free(status);
      boxpath_free(bpath);
      return res;
    }
    free(status);

    dirid = tag_value(buf,"folder_id");
    free(buf);
    
    // aggiungo 1 entry all'hash
    newdir = boxdir_create();
    newdir->id = dirid;
    xmlHashAddEntry(allDirs, path, newdir);
    // upd parent
    aFile = (boxfile *) malloc(sizeof(boxfile));
    aFile->id = strdup(dirid);
    aFile->name = strdup(bpath->base);
    aFile->size = 0;
    aFile->ctime = now;
    aFile->mtime = now;
	LOCKDIR(bpath->dir);
    xmlListPushBack(bpath->dir->folders, aFile);
	UNLOCKDIR(bpath->dir);    
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
  time_t now = time(NULL);

  if(bpath->dir) {
    aFile = (boxfile *) malloc(sizeof(boxfile));
    aFile->name = strdup(bpath->base);
    aFile->size = 0;
    aFile->id = NULL;
    aFile->ctime = now;
    aFile->mtime = now;
	LOCKDIR(bpath->dir);
    xmlListPushBack(bpath->dir->files,aFile);
    UNLOCKDIR(bpath->dir);
    boxpath_free(bpath);
  } else {
    syslog(LOG_WARNING, "UH oh... wrong path %s",path);
    res = -ENOTDIR;
  }
  
  return res;
}

int get_key() {
  int res = 0;
  char * buf = NULL;
  char * status = NULL;
  char gkurl[256];

  sprintf(gkurl, "%s" API_GET_AUTH_TOKEN "&ticket=%s", proto, ticket);
  buf = http_fetch(gkurl);
  status = node_value(buf,"status");
  if(strcmp(status,API_GET_AUTH_TOKEN_OK)) {
    res = 1;
  }
  if(!res) {
    auth_token = node_value(buf,"auth_token");
    tot_space = tag_lvalue(buf,"space_amount");
    used_space = tag_lvalue(buf,"space_used");
  }

  if(buf) free(buf);
  if(status) free(status);

  return res;
}

int get_tree() {
  int res = 0;
  int fd;
  char gkurl[512];

  sprintf(gkurl, "%s" API_GET_ACCOUNT_TREE "%s", proto, auth_token);
  fd = mkstemp(treefile);
  if(fd!=-1) close(fd);
  res = http_fetch_file(gkurl,treefile);

  return res;
}

int walk_setid(boxfile * aFile, boxfile * info)
{
  if(!strcmp(aFile->name,info->name)) {
    aFile->id = info->id;
    aFile->size = info->size;
    return 0;
  }

  return 1;
}

void set_filedata(const boxpath * bpath, char * fid, long fsize)
{
  boxfile * aFile;

  aFile = (boxfile *) malloc(sizeof(boxfile));
  aFile->name = bpath->base;
  aFile->id = fid;
  aFile->size = fsize;
  aFile->mtime = time(NULL);
  xmlListWalk(bpath->dir->files,(xmlListWalker)walk_setid,aFile);
  free(aFile);
}


int api_open(const char * path, const char * pfile){
  int res = 0;
  char gkurl[512]="";
  boxpath * bpath = boxpath_from_string(path);
  if(!boxpath_getfile(bpath)) res = -ENOENT;
  
  if(!res) {
    sprintf(gkurl, "%s" API_DOWNLOAD "%s/%s", proto, auth_token, bpath->file->id);
    res = http_fetch_file(gkurl, pfile);
  }
  
  boxpath_free(bpath);  
  return res;
}

typedef struct filldata_t {
  fuse_fill_dir_t filler;
  void * buf;
} filldata;

int walk_filler (boxfile * file, filldata * data)
{
  data->filler(data->buf, file->name, NULL, 0);
    
  return 1;
}

int api_readdir(const char * path, fuse_fill_dir_t filler, void * buf)
{
  int res = 0;
  boxdir * dir;
  filldata * data = NULL;
  
  dir = (boxdir *) xmlHashLookup(allDirs,path);
  if (dir==NULL) return -EINVAL;

  filler(buf, ".", NULL, 0);
  filler(buf, "..", NULL, 0);

  data = (filldata *) malloc(sizeof(filldata));
  data->buf = buf;
  data->filler = filler;
  LOCKDIR(dir);
  xmlListWalk(dir->folders,(xmlListWalker)walk_filler,data);
  xmlListWalk(dir->files, (xmlListWalker)walk_filler,data);
  UNLOCKDIR(dir);

  free(data);

  return res;
}

int api_subdirs(const char * path)
{
  boxdir * dir;
  
  dir = (boxdir *) xmlHashLookup(allDirs,path);
  if (dir==NULL) return -1;

  return xmlListSize(dir->folders);
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
	if(bpath->is_dir) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2 + api_subdirs(path);
	} else {
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
	}
	boxpath_free(bpath);
	return 0;
}

int api_removedir(const char * path)
{
  int res = 0;
  boxpath * bpath = boxpath_from_string(path);
  if(!boxpath_getfile(bpath)) return -EINVAL;
  
  char gkurl[512];
  char *buf, *status;
  
  if(!bpath->dir && !bpath->is_dir) return -ENOENT;
  sprintf(gkurl, "%s" API_RMDIR "%s&target_id=%s", proto, auth_token, bpath->file->id);
  buf = http_fetch(gkurl);
  status = node_value(buf,"status");
  if(strcmp(status,API_UNLINK_OK)) {
    res = -EPERM;
  }
  free(status);
  free(buf);

  if(!res) {
    //remove it from parent's subdirs...
    LOCKDIR(bpath->dir);
    boxpath_removefile(bpath);
    UNLOCKDIR(bpath->dir);
    //...and from dir list
    xmlHashRemoveEntry(allDirs, path, NULL);
  }
  
  boxpath_free(bpath);  
  return res;
}

int api_removefile(const char * path)
{
  int res = 0;
  boxpath * bpath = boxpath_from_string(path);
  char gkurl[512];
  char *buf, *status;

  if(!bpath->dir) res = -ENOENT;
  else {
    
    //remove it from box.net
    boxpath_getfile(bpath);
    sprintf(gkurl, "%s" API_UNLINK "%s&target_id=%s", proto, auth_token,
      bpath->file->id);
    buf = http_fetch(gkurl);
    status = node_value(buf,"status");
    if(strcmp(status,API_UNLINK_OK)) {
      res = -ENOENT;
    }
    free(status);
    free(buf);

    //remove it from the list
    if(res==0) {
	  LOCKDIR(bpath->dir);
	  boxpath_removefile(bpath);
	  UNLOCKDIR(bpath->dir);
    }
  }
  boxpath_free(bpath);

  return res;
}

//Move and rename funcs, new version
int do_api_move(boxpath * bsrc, boxpath * bdst)
{
	char * buf = NULL, * status;
	char gkurl[1024];
	int res = 0;

	LOCKDIR(bsrc->dir);
	sprintf(gkurl, "%s" API_MOVE "%s&target=%s&target_id=%s&destination_id=%s", 
		  proto, auth_token, (bsrc->is_dir ? "folder" : "file"),
		  bsrc->file->id, bdst->dir->id);
	buf = http_fetch(gkurl);
	status = node_value(buf,"status");
	if(strcmp(status,API_MOVE_OK)) {
	  res = -EINVAL;
	} else {
	    boxpath_removefile(bsrc);
	    
		LOCKDIR(bdst->dir);
		xmlListPushBack((bsrc->is_dir ? bdst->dir->folders : bdst->dir->files),
		  bsrc->file);
		UNLOCKDIR(bdst->dir);
	}
	UNLOCKDIR(bsrc->dir);
	
	free(status);free(buf);
	return res;
}
int do_api_rename(boxpath * bsrc, boxpath * bdst)
{
	char * buf = NULL, * status;
	char gkurl[1024];
	int res = 0;

	LOCKDIR(bsrc->dir);
	sprintf(gkurl, "%s" API_RENAME "%s&target=%s&target_id=%s&new_name=%s",
		  proto, auth_token, (bsrc->is_dir ? "folder" : "file"),
		  bsrc->file->id, xmlURIEscapeStr(bdst->base,""));
	buf = http_fetch(gkurl);
	status = node_value(buf,"status");
	if(strcmp(status,API_RENAME_OK)) {
		res = -EINVAL;
	} else {
		boxpath_renamefile(bsrc, bdst->base);
	}
	UNLOCKDIR(bsrc->dir);

	free(status);free(buf);
	return res;
}
int api_rename_v2(const char * from, const char * to)
{
	int res = 0;
	boxpath * bsrc = boxpath_from_string(from);
	boxpath * bdst = boxpath_from_string(to);
	if(!boxpath_getfile(bsrc)) return -EINVAL; 
	boxpath_getfile(bdst);

	if(bsrc->dir!=bdst->dir) {
		res=do_api_move(bsrc, bdst);
	}
	if(!res && strcmp(bsrc->base, bdst->base)) {
		res = do_api_rename(bsrc,bdst);
	}
	if(!res && bsrc->is_dir) {
	    boxtree_movedir(from, to);
	}

	boxpath_free(bsrc);
	boxpath_free(bdst);
	return res;
}

void api_upload(const char * path, const char * tmpfile)
{
  postdata_t buf = post_init();
  char * res = NULL;
  char gkurl[512];
  char * fid;
  long fsize;
  boxpath * bpath = boxpath_from_string(path);

  if(bpath->dir) {
    sprintf(gkurl, "%s" API_UPLOAD "%s/%s", proto, auth_token, bpath->dir->id);
    fsize = filesize(tmpfile);
    if(fsize) {
      post_addfile(buf, bpath->base, tmpfile);
      res = http_postfile(gkurl, buf);
      post_free(buf);
      fid = attr_value(res,"id");
      if(fid) set_filedata(bpath ,fid, fsize);
      free(res);
    }
  } else {
    syslog(LOG_ERR,"Couldn't upload file %s",bpath->base);
  }
  boxpath_free(bpath);
}


/*
 * Login to box.net, get the auth_token
 */
int api_init(int* argc, char*** argv) {

  int res = 0;

  /* parse command line arguments */
  if (parse_options (argc, argv, &options))
      return 1;  
  
  xmlInitParser();
  openlog("boxfs", LOG_PID, LOG_USER);
  proto = options.secure ? PROTO_HTTPS : PROTO_HTTP;
  
  res = get_ticket(&options);
  if(res) BOX_ERR("Unable to initialize Box.net connection.\n");
  else {
    res = get_key();
    if(res) BOX_ERR("Error while logging in to Box.net.\n");
    else {
      res = get_tree();
      if(res) BOX_ERR("Error while fetching user file tree\n");
    }
  }
  
  if(!res) {
    boxtree_setup(treefile);
    unlink(treefile);
  
    syslog(LOG_INFO, "Filesystem mounted on %s", options.mountpoint);
    if(options.verbose) syslog(LOG_DEBUG, "Auth token is: %s", auth_token);
  }
  free_options (&options);
  return res;
}
