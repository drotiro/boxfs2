#include "boxcache.h"
#include "boxutils.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>

static char *cache_dir = NULL;
static time_t expire = 0;

void cache_init(const char * path, int expire_time)
{
	//one-time initialization
	if(!cache_dir && path) {
		cache_dir = strdup(path);
		expire = expire_time * 60;
	}
}

char * make_path(const char * key)
{
	if(!cache_dir) return NULL;
	if(strstr(key, "../")) return NULL;
	
	return pathappend(cache_dir, key);
}

char * cache_get(const char * key)
{
	struct stat sb;
	int sres;
	char * fname = make_path(key);
	FILE * kf;
	char * v;
	off_t flen, er;

        kf = fopen(fname, "r");
	if(!kf) { free(fname); return NULL; }

        sres = stat(fname, &sb);
        if(sres) { free(fname); return NULL; }
	flen = sb.st_size;
	if(expire && ((time(NULL) - sb.st_mtime) > expire)) {
		fclose(kf);
		unlink(fname);
		free(fname);
		return NULL;
	}

	
	v = malloc(flen+1);
	if (v) {
		er = fread(v, 1, flen, kf);
		v[er] = 0;
	}
	
	fclose(kf);
	free(fname);
	return v;
}

void   cache_rm(const char * key)
{
	char * fname = make_path(key);

	if(fname) {
		unlink(fname);
		free(fname);
	}
}

void   cache_put(const char * key, const char * val)
{
	char * fname = make_path(key);
	FILE * kf = fopen(fname, "w");
	free(fname);
	
	if(!kf) return;
	
	fwrite(val, strlen(val), 1, kf);
	fclose(kf);
}
