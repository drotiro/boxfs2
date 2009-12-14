/***************************************

  DR: Interazione con il sito
  
  This software is licensed under the 
  GPLv2 license.

***************************************/

#include "boxapi.h"
//DR:TEST
#include "boxpath.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libgen.h>
#include <termios.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>

#include <pthread.h>

#include <libxml/nanohttp.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/uri.h>

#define BOX_ERR(MSG) fprintf(stderr,MSG);
#define MAXBUF 4096
#define FALSE 0
#define TRUE 1

#define API_KEY_VAL "2uc9ec1gtlyaszba4h6nixt7gyzq3xir"
#define API_KEY "&api_key=" API_KEY_VAL
#define API_REST_BASE "http://www.box.net/api/1.0/rest?action="
#define API_GET_TICKET API_REST_BASE "get_ticket" API_KEY
#define API_GET_TICKET_OK "get_ticket_ok"
#define API_LOGIN_URL "http://www.box.net/api/1.0/auth/"
#define API_GET_AUTH_TOKEN API_REST_BASE "get_auth_token" API_KEY
#define API_GET_AUTH_TOKEN_OK "get_auth_token_ok"
#define API_GET_ACCOUNT_TREE API_REST_BASE "get_account_tree&params%5B%5D=nozip&folder_id=0" \
        API_KEY "&auth_token="
#define API_GET_ACCOUNT_TREE_OK "listing_ok"
#define API_DOWNLOAD "http://box.net/api/1.0/download/"
#define API_UPLOAD "http://upload.box.net/api/1.0/upload/"
#define API_CREATE_DIR API_REST_BASE "create_folder" API_KEY "&auth_token="
#define API_CREATE_DIR_OK "create_ok"
#define API_RENAME API_REST_BASE "rename" API_KEY "&auth_token="
#define API_RENAME_OK "s_rename_node"
#define API_MOVE API_REST_BASE "move" API_KEY "&auth_token="
#define API_MOVE_OK "s_move_node"
#define API_UNLINK API_REST_BASE "delete&target=file" API_KEY "&auth_token="
#define API_UNLINK_OK "s_delete_node"
#define API_RMDIR API_REST_BASE "delete&target=folder" API_KEY "&auth_token="
#define API_RMDIR_OK API_UNLINK_OK 
#define API_LOGOUT API_REST_BASE "logout" API_KEY "&auth_token="

#define LOCKDIR(dir) /*syslog(LOG_INFO, "LOCKING DIR %s", dir->id);*/ pthread_mutex_lock(dir->dirmux);
#define UNLOCKDIR(dir) pthread_mutex_unlock(dir->dirmux); /*syslog(LOG_INFO, "UNLOCKING DIR %s", dir->id);*/

/* globals, written during initialization */
char *ticket = NULL, *auth_token = NULL;
char treefile[] = "/tmp/boxXXXXXX";
long tot_space, used_space;

/* command-line options */
typedef struct box_options_t
{
    char* user;
    char* password;
    char* mountpoint;
} box_options;


void show_usage ();
void show_fuse_usage ();
int  read_conf_file (const char* file_name, struct box_options_t* options);

void wipeopt(char * opt) 
{
	int i, l=strlen(opt);
	for(i = 0; i < l; ++i) opt[i]=0;
}

int parse_options (int* argc, char*** argv, struct box_options_t* options)
{
    int c;
    char* pass_file = NULL;

    options->user = NULL;
    options->password = NULL;
    options->mountpoint = NULL;

    while ((c = getopt (*argc, *argv, "Hhu:p:f:")) != -1) {
        switch (c) {
        case 'H':
            show_fuse_usage ();
            return 1;
        case 'h':
            show_usage ();
            return 1;
        case 'u':
            options->user = strdup (optarg);
            break;
        case 'p':
            options->password = strdup (optarg);
			wipeopt(optarg);
            break;
        case 'f':
            pass_file = optarg;
            break;
        case '?':
            if (optopt == 'u' || optopt == 'p')
                printf ("Option -%c requires an argument.\n", optopt);
            return 1;
        }
    }

    if (pass_file) {
        if (read_conf_file (pass_file, options)) {
            show_usage();
            return 1;
        }
    }

    /* check for mountpoint presence */
    if (optind == *argc) {
        if(options->mountpoint) {
            optind--;
            (*argv)[optind] = strdup(options->mountpoint);
        } else {
            BOX_ERR("Error: mountpoint not specified\n"
                "You should pass it on the command line or in the config file.\n");
            return 1;
        }
    }

    *argc -= optind - 1;
    *argv += optind - 1;

    return 0;
}


void free_options (struct box_options_t* options)
{
    if (options->user)
        free (options->user);
    if (options->password)
        free (options->password);
    if (options->mountpoint)
        free(options->mountpoint);
}


void show_usage ()
{
    printf ("Usage: boxfs [options] [mountPoint] [FUSE Mount Options]\n\n");
    printf ("Common options:\n");
    printf ("  -H                show optional FUSE mount options\n");
    printf ("  -u login          box.net login name\n");
    printf ("  -p password       box.net password\n");
    printf ("  -f conffile       file containing configuration options\n\n");
    printf ("File passed in -f option can have lines such as:\n");
    printf ("username = mrsmith\n");
    printf ("mountpoint = /path/to/folder\n");
    printf ("password = secret\n\n");
}


void show_fuse_usage ()
{
    int argc = 2;
    char* argv[] = { "boxfs", "-h" };

    fuse_main (argc, argv, NULL);
}

void trim(char *s) {
	if (!s) return;
    char *p = s;
    int l = strlen(p);

    while(isspace(p[l - 1])) p[--l] = 0;
    while(* p && isspace(* p)) ++p, --l;

    memmove(s, p, l + 1);
}

int read_conf_file (const char* file_name, box_options* options)
{
    FILE *f;
    int res = 0, nline = 0;
    char *optkey=NULL, *optval = NULL, line[1024]="";
    const char KEY_USER [] = "username";
    const char KEY_PASS [] = "password";
    const char KEY_MOUNT [] = "mountpoint";
    const char SEP [] = "=";

    if ((f = fopen(file_name, "r")) == NULL) {
        fprintf(stderr, "cannot open %s\n", file_name);
        return 1;
    }
	//bzero(options, sizeof(box_options));
	
    do {
	++nline;
        if (fgets(line, sizeof(line), f)==NULL) break;
	trim(line);
        if(*line=='#' || strlen(line) == 0) continue; // skip comments
		
        optkey = strtok(line,SEP);
        optval = strtok(NULL,SEP);
        if(optkey == NULL || optval == NULL) {
            fprintf(stderr, "Invalid line #%d in credentials file\n", nline);
            res = 1;
            break;
        }
        trim(optkey);
	trim(optval);

        if (!strcmp(optkey,KEY_USER)) options->user = strdup(optval);
        else if (!strcmp(optkey,KEY_PASS)) options->password = strdup(optval);
        else if (!strcmp(optkey,KEY_MOUNT)) options->mountpoint = strdup(optval);
        else { 
            fprintf(stderr,"Invalid option %s in file %s (line #%d)\n", optkey, file_name, nline);
            res = 1;
            break;
        }
    } while(!feof(f));
    fclose(f);

    return res;
};

boxdir * create_dir()
{
  boxdir * aDir;
  aDir = (boxdir *) malloc(sizeof(boxdir));
  aDir->files = xmlListCreate(NULL, NULL); // TODO: Deallocator!
  aDir->folders = xmlListCreate(NULL, NULL);
  aDir->dirmux = malloc(sizeof(pthread_mutex_t));
  pthread_mutex_init(aDir->dirmux, NULL);
  
  return aDir;
}

char * http_fetch(const char * url)
{ 
  void * ctx;
  int len = 0;
  char * buf = NULL, *ct;
  
  ctx = xmlNanoHTTPOpen(url, &ct);
  if(!ctx) {
    syslog(LOG_ERR, "Connection problem fetching url %s",url);
  } else {
    len = xmlNanoHTTPContentLength(ctx);
    if(len <= 0) len = MAXBUF;
    buf = (char*)malloc(len);
    len = xmlNanoHTTPRead(ctx,buf,len);
    buf[len] = 0;
    xmlNanoHTTPClose(ctx);
  }
  
  return buf;
}

long filesize(const char * localpath)
{
  long fs;
  FILE * alf;
  
  alf = fopen(localpath,"r");
  fseek(alf, 0L, SEEK_END);
  fs = ftell(alf);
  fclose(alf);
  
  return fs;
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
  
  sprintf(gkurl,API_LOGOUT "%s", auth_token);
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
  
  xmlNanoHTTPCleanup();
  xmlCleanupParser();
  if(allDirs) xmlHashFree(allDirs, NULL); // TODO: Deallocator!
}

int http_fetch_file(const char * url, const char * dest)
{ 
  void * ctx; 
  int res = 1;
  char *ct;
  
  ctx = xmlNanoHTTPOpen(url, &ct);
  if(!ctx) {
    syslog(LOG_ERR, "Connection problem fetching url %s",url);
  } else {
    res = xmlNanoHTTPSave(ctx, dest);    
  }
  
  return res;
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

void post_add(char * buf, const char * name, const char * val)
{
  sprintf(buf+strlen(buf),"--BfsBy\ncontent-disposition: form-data; name=\"%s\"\n\n%s\n",
        name, val);
}

long post_addfile(char ** rbuf, const char * name, const char * tmpfile, long fsize)
{
  FILE * tf;
  int hlen;
  char * buf = NULL;
  long bufsize = fsize+256+strlen(name);
  
  buf = malloc(bufsize);
  if(!buf) { 
    syslog(LOG_ERR, "Cannot allocate %ld bytes of memory",bufsize);
    *rbuf = NULL;
    return -1;
  }
  buf[0]=0;
  *rbuf=buf;
  
  sprintf(buf,"--BfsBy\ncontent-disposition: form-data; name=\"new_file0\"; filename=\"%s\"\n"
            "Content-Type: application/octet-stream\nContent-Transfer-Encoding: binary\n\n", name);
  hlen = strlen(buf);
  tf = fopen(tmpfile,"r");
  fread(buf+hlen, 1, fsize, tf);
  fclose(tf);
  memcpy(buf+hlen+fsize,"\n--BfsBy--\n\0",12);
  return fsize+hlen+11;  
}


void http_post(const char * url, const char * data)
{
  void * ctx;
  char contentType[512] = "multipart/form-data, boundary=BfsBy";
  char * ct = contentType;
  
  ctx = xmlNanoHTTPMethod(url, "POST", data, &ct, 
        NULL, strlen(data));
  xmlNanoHTTPClose(ctx);
  free(ct);
}

char * http_postfile(const char * url, const char * data, long size)
{
  void * ctx;
  int len = 0;
  char contentType[512] = "multipart/form-data, boundary=BfsBy";
  char * ct = contentType;
  char * buf;

  ctx = xmlNanoHTTPMethod(url, "POST", data, &ct,
        NULL, size);
        
  len = xmlNanoHTTPContentLength(ctx);
  //fprintf(stderr, "Response content length: %d\n",len);
  if(len <= 0) len = MAXBUF;
  buf = (char*)malloc(len);
  len = xmlNanoHTTPRead(ctx,buf,len);
  buf[len] = 0;
  xmlNanoHTTPClose(ctx);
  free(ct);
  //fprintf(stderr,"RESPONSE:\n%s\n",buf);

  return buf;  
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
  char postpar[4096]="";
  char gkurl[512];
  char* value;
  
  buf = http_fetch(API_GET_TICKET);
  status = node_value(buf,"status");
  if(strcmp(status,API_GET_TICKET_OK)) {
    res = 1;
  }
  if(!res) ticket = node_value(buf,"ticket");
  
  if(buf) free(buf);
  if(status) free(status);

  /* autologin using http POST */
  /*
  login = askuser("Login: ",FALSE);
  password = askuser("Password: ",TRUE);
  */
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
  
  return res;
}

void tree_splitpath(const char * path, boxdir ** par, char ** file)
{
  boxdir * parent = NULL;
  char * odir = strdup(path), *dir;
  
  dir = dirname(odir);
  *file = basename(*file);
  parent = xmlHashLookup(allDirs,dir);
  *par = parent;  

  free(odir);
}

void api_getusage(long * tot_sp, long * used_sp)
{
  *tot_sp = tot_space;
  *used_sp = used_space;
}

int api_createdir(const char * path)
{
  int res = 0;
  char * obase = strdup(path), *base = obase, *encbase;
  boxdir *parent, *newdir;
  boxfile * aFile;
  char * dirid, *buf, *status;
  char gkurl[512];

  tree_splitpath(path, &parent, &base);
  if(parent) {
	//syslog(LOG_WARNING, "creating dir %s (escaped: %s) ",base,xmlURIEscapeStr(base,""));
    sprintf(gkurl,API_CREATE_DIR "%s&parent_id=%s&name=%s&share=0", 
          auth_token, parent->id, xmlURIEscapeStr(base,""));
    buf = http_fetch(gkurl);
    status = node_value(buf,"status");
    if(strcmp(status,API_CREATE_DIR_OK)) {
      res = -EINVAL;
      free(buf); free(status);
      return res;
    }
    free(status);

    dirid = tag_value(buf,"folder_id");
    free(buf);
    
    // aggiungo 1 entry all'hash
    newdir = create_dir();
    newdir->id = dirid;
    xmlHashAddEntry(allDirs, path, newdir);
    // upd parent
    aFile = (boxfile *) malloc(sizeof(boxfile));
    aFile->id = strdup(dirid);
    aFile->name = strdup(base);
	LOCKDIR(parent);
    xmlListPushBack(parent->folders,aFile);
	UNLOCKDIR(parent);
    
  } else {
    syslog(LOG_WARNING, "UH oh... wrong path %s",path);
    res = -EINVAL;
  }
  free(obase);

  return res;
}


int api_create(const char * path)
{
  int res = 0;
  char * obase = strdup(path), *base = obase;
  boxdir * parent;
  boxfile * aFile;

  tree_splitpath(path, &parent, &base);
  if(parent) {
    aFile = (boxfile *) malloc(sizeof(boxfile));
    aFile->name = strdup(base);
    aFile->size = 0;
    aFile->id = NULL;
	LOCKDIR(parent);
    xmlListPushBack(parent->files,aFile);
    UNLOCKDIR(parent);
  } else {
    syslog(LOG_WARNING, "UH oh... wrong path %s",path);
    res = -EINVAL;
  }
  free(obase);
  
  return res;
}

int get_key() {
  int res = 0;
  char * buf = NULL;
  char * status = NULL;
  char gkurl[256]=API_GET_AUTH_TOKEN "&ticket=";

  strcat(gkurl, ticket);
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
  char gkurl[512]=API_GET_ACCOUNT_TREE;

  strcat(gkurl, auth_token);
  fd = mkstemp(treefile);
  if(fd!=-1) close(fd);
  res = http_fetch_file(gkurl,treefile);

  return res;
}

int walk_rename(boxfile * aFile, boxfile * info)
{
  if(!strcmp(aFile->id,info->id)) {
    aFile->name=info->name;
	return 0;
  }
  return 1;	
}

int walk_rename_byname(boxfile * aFile, char * names[2])
{
  if(!strcmp(aFile->name,names[0])) {
    aFile->name=names[1];
	return 0;
  }
  return 1;	
}

int walk_getid(boxfile * aFile, boxfile * info)
{
  if(!strcmp(aFile->name,info->name)) {
    info->id = aFile->id;
    return 0;
  }
  return 1;
}

char * get_fileid(const char * fname)
{
  char * obase = strdup(fname), *base = obase;
  char * res = NULL;
  boxdir * parent;
  boxfile * aFile;

  tree_splitpath(fname, &parent, &base);
  if(parent) {
    aFile = (boxfile *) malloc(sizeof(boxfile));
    aFile->name = base;
    aFile->id = NULL;
    xmlListWalk(parent->files,(xmlListWalker)walk_getid,aFile);
    res = aFile->id;
    free(aFile);
  }

  free(obase);
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

void set_filedata(const char * fname, char * fid, long fsize)
{
  char * obase = strdup(fname), *base = obase;
  boxdir * parent;
  boxfile * aFile;

  tree_splitpath(fname, &parent, &base);
  if(parent) {
    aFile = (boxfile *) malloc(sizeof(boxfile));
    aFile->name = base;
    aFile->id = fid;
    aFile->size = fsize;
    xmlListWalk(parent->files,(xmlListWalker)walk_setid,aFile);
    free(aFile);
  }
  free(obase);
}


int api_open(const char * path, const char * pfile){
  int res = 0;
  char gkurl[512]="";
  
  sprintf(gkurl, API_DOWNLOAD "%s/%s", auth_token, get_fileid(path));
  res = http_fetch_file(gkurl, pfile);
  
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
  int res = 0;
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

void scan_rmdir(boxdir * dir, const char * path, const char * name)
{
  int len = strlen(path);
  if(!strncmp( path, name, len)) {
    if((strlen(name) > len) && (name[len]=='/')) 
      xmlHashRemoveEntry(allDirs, name, NULL);
    else if(!strcmp(name, path))
      xmlHashRemoveEntry(allDirs, name, NULL);
  }
}

int walk_remove(boxfile * aFile, boxfile * info)
{
  if(!strcmp(aFile->name,info->name)) {
    info->size = 0;
    xmlListRemoveFirst((xmlListPtr)info->id , aFile);
	info->id = (char*) aFile; //return ref to deleted item
    return 0;
  }
  return 1;
}

int api_removedir(const char * path)
{
  int res = 0;
  char * obase = strdup(path), *base = obase;
  boxdir * parent, * thedir = NULL;;
  boxfile * aFile;
      
  char gkurl[512];
  char *buf, *status;
  
  thedir = xmlHashLookup(allDirs, path);
  if(!thedir) return -ENOENT;

  sprintf(gkurl, API_RMDIR "%s&target_id=%s", auth_token, thedir->id);
  buf = http_fetch(gkurl);
  status = node_value(buf,"status");
  if(strcmp(status,API_UNLINK_OK)) {
    res = -EPERM;
  }
  free(status);
  free(buf);

  xmlHashScan(allDirs, (xmlHashScanner)scan_rmdir, (void*) path);

  //remove it from parent's subdirs
  tree_splitpath(path, &parent, &base);
  if(parent) {
    aFile = (boxfile *) malloc(sizeof(boxfile));
    aFile->name = base;
    aFile->id = (char*) parent->folders; //ugly
	LOCKDIR(parent);
    xmlListWalk(parent->folders, (xmlListWalker)walk_remove, aFile);
    UNLOCKDIR(parent);
    free(aFile);
  }
    
  return res;
}

int api_removefile(const char * path)
{
  int res = 0;
  char * obase = strdup(path), *base = obase;
  boxdir * parent;
  boxfile * aFile;
  char gkurl[512];
  char *buf, *status;

  tree_splitpath(path, &parent, &base);
  if(!parent) res = -ENOTDIR;
  else {
    aFile = (boxfile *) malloc(sizeof(boxfile));
    aFile->name = base;
    
    //remove it from box.net
    aFile->id = NULL;
    xmlListWalk(parent->files, (xmlListWalker)walk_getid, aFile);
    sprintf(gkurl, API_UNLINK "%s&target_id=%s", auth_token, aFile->id);
    buf = http_fetch(gkurl);
    status = node_value(buf,"status");
    if(strcmp(status,API_UNLINK_OK)) {
      res = -ENOENT;
    }
    free(status);
    free(buf);

    //remove it from the list
    if(res==0) {
      aFile->size = -ENOENT;
      aFile->id = (char*) parent->files; //ugly
	  LOCKDIR(parent);
      xmlListWalk(parent->files, (xmlListWalker)walk_remove, aFile);
	  UNLOCKDIR(parent);
      res = aFile->size;
    }
    free(aFile);  
  }
  free(obase);

  return res;
}

int move_and_rename(const char * path, const char * newpath);

int api_rename(const char * from, const char * to)
{
	char * buf = NULL, *status;
	int res = 0;
	char * ofrom = strdup(from), * oto = strdup(to);
	char *fbase=ofrom, *tbase=oto;
	boxdir * fparent, * tparent;
	char gkurl[1024];
	char * fid=NULL;
	boxfile * aFile;
	boxdir * aDir;
	
	tree_splitpath(from, &fparent, &fbase);
	tree_splitpath(to, &tparent, &tbase);
	fid = get_fileid(from);
	//if src & dst dir are the same we can just rename
	if(fparent==tparent) {
		//syslog(LOG_DEBUG,"RENAME: from %s [%s] to %s [%s], fid=%s",from, fbase,
	    //   to, tbase, fid);
		if(fid) {
			//syslog(LOG_INFO,"samedir file rename");
			LOCKDIR(fparent);
			sprintf(gkurl,API_RENAME "%s&target=file&target_id=%s&new_name=%s", 
				  auth_token, fid, xmlURIEscapeStr(tbase,""));
			buf = http_fetch(gkurl);
			status = node_value(buf,"status");
			if(strcmp(status,API_RENAME_OK)) {
			  res = -EINVAL;
			} else {
				aFile = (boxfile *) malloc(sizeof(boxfile));
				aFile->id = fid;
				aFile->name=strdup(tbase);
				xmlListWalk(fparent->files,(xmlListWalker)walk_rename,aFile);
				free(aFile);
			}
			free(status);free(buf);
			UNLOCKDIR(fparent);
			return res;
		} else {
			aDir = xmlHashLookup(allDirs,from);
			//syslog(LOG_INFO,"samedir dir rename");
			LOCKDIR(fparent);
			sprintf(gkurl,API_RENAME "%s&target=folder&target_id=%s&new_name=%s", 
				  auth_token, aDir->id, xmlURIEscapeStr(tbase,""));
			buf = http_fetch(gkurl);
			status = node_value(buf,"status");
			if(strcmp(status,API_RENAME_OK)) {
			  res = -EINVAL;
			} else {
				LOCKDIR(aDir);
				xmlHashRemoveEntry(allDirs, from, NULL);
				xmlHashAddEntry(allDirs, to, aDir);
				UNLOCKDIR(aDir);
				char ** names = (char **) malloc (2*sizeof(char*));
				names[0]=fbase; names[1]=tbase;
				xmlListWalk(fparent->folders, (xmlListWalker)walk_rename_byname, 
				            names);
				free(names);				
			}
			free(status);free(buf);
			UNLOCKDIR(fparent);
			return res;
		}
	}
	//move + (rename)
	if(strcmp(fbase,tbase)) return move_and_rename(from,to);
	//syslog(LOG_DEBUG,"MOVE: from %s [%s] to %s [%s], fid=%s",from, fbase,
	//       to, tbase, fid);
	if(fid) {
		//moving a file
		LOCKDIR(fparent);
		sprintf(gkurl,API_MOVE "%s&target=file&target_id=%s&destination_id=%s", 
			  auth_token, fid, tparent->id);
		buf = http_fetch(gkurl);
		status = node_value(buf,"status");
		if(strcmp(status,API_MOVE_OK)) {
		  res = -EINVAL;
		} else {
			aFile = (boxfile *) malloc(sizeof(boxfile));
			aFile->id = (char *) fparent->files;
			aFile->name=strdup(fbase);
			xmlListWalk(fparent->files,(xmlListWalker)walk_remove,aFile);
			LOCKDIR(tparent);
			xmlListPushBack(tparent->files, (boxfile*)aFile->id);
			UNLOCKDIR(tparent);
			free(aFile);
		}
		free(status);free(buf);
		UNLOCKDIR(fparent);
		//verificare se c'è anche un rename!!!
		return res;		
	} else {
		//moving a dir...
		LOCKDIR(fparent);
		aDir = xmlHashLookup(allDirs,from);
		sprintf(gkurl,API_MOVE "%s&target=folder&target_id=%s&destination_id=%s", 
			  auth_token, aDir->id, tparent->id);
		buf = http_fetch(gkurl);
		status = node_value(buf,"status");
		if(strcmp(status,API_MOVE_OK)) {
		  res = -EINVAL;
		} else {
			LOCKDIR(aDir);
			xmlHashRemoveEntry(allDirs, from, NULL);
			xmlHashAddEntry(allDirs, to, aDir);
			UNLOCKDIR(aDir);
			aFile = (boxfile *) malloc(sizeof(boxfile));
			aFile->id = (char *) fparent->folders;
			aFile->name=strdup(fbase);
			xmlListWalk(fparent->folders,(xmlListWalker)walk_remove,aFile);
			LOCKDIR(tparent);
			xmlListPushBack(tparent->folders, (boxfile*)aFile->id);
			UNLOCKDIR(tparent);
			free(aFile);	
		}
		free(status);free(buf);
		UNLOCKDIR(fparent);
		return res;
	}
	
	return res;
}

int move_and_rename(const char * path, const char * newpath)
{
	char * odir = strdup(path), *onew = strdup(newpath);
	char * to1;
	int res;

	//syslog(LOG_INFO,"Starting 2-step rename");
	//step 1: local rename
	to1 = malloc(strlen(path)+strlen(newpath)+1);
	to1[0]=0;
	strcat(to1,dirname(odir));
	strcat(to1,"/");
	strcat(to1,basename(onew));
	syslog(LOG_INFO,"%s => %s",path,to1);
	res = api_rename(path,to1);
	if(res) return res;
	//step2: move
	res = api_rename(to1,newpath);

	free(odir); free(onew);
	free(to1);

	return res;
}

void api_upload(const char * path, const char * tmpfile)
{
  char * obase = strdup(path), *base = obase;
  char * buf = NULL;
  char * res = NULL;
  char gkurl[512];
  char * fid;
  boxdir * parent;
  long fsize, psize;

  tree_splitpath(path, &parent, &base);
  if(parent) {
    sprintf(gkurl,API_UPLOAD "%s/%s", auth_token, parent->id);
    fsize = filesize(tmpfile);
    if(fsize) {
      psize = post_addfile(&buf, base, tmpfile, fsize);
      res = http_postfile(gkurl, buf, psize);
      free(buf);
      fid = attr_value(res,"id");
      if(fid) set_filedata(path ,fid, fsize);
      free(res);
    }
  } else {
    syslog(LOG_ERR,"Couldn't upload file %s",base);
  }
  free(obase);
}


/*
 * Login to box.net, get the auth_token
 */
int api_init(int* argc, char*** argv) {

  int res = 0;
  struct box_options_t options;

  /* parse command line arguments */
  if (parse_options (argc, argv, &options))
      return 1;

  xmlInitParser();
  xmlNanoHTTPInit();
  openlog("boxfs", LOG_PID, LOG_USER);
  
  res = get_ticket(&options);
  if(res) {
    BOX_ERR("Unable to initialize Box.net connection.\n");
    free_options (&options);
    return 1;
  }
  
  res = get_key();
  if(res) {
    BOX_ERR("Error while logging in to Box.net.\n");
    free_options (&options);
    return 1;
  }

  res = get_tree();
  if(res) {
    BOX_ERR("Error while fetching user file tree\n");
    free_options (&options);
    return 1;
  }
  
  boxpath_setup_tree(treefile);
  unlink(treefile);
  free_options (&options);
  
  syslog(LOG_INFO, "filesystem mounted. Auth token: %s", auth_token);
  return 0;  
}
