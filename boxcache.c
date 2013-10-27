#include "boxcache.h"
#include "boxutils.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static char *cache_dir = NULL;

void cache_init(const char * path)
{
	//one-time initialization
	if(!cache_dir) cache_dir = strdup(path);
}

char * make_path(const char * key)
{
	if(!cache_dir) {
		fprintf(stderr, "ERROR: cache_init has not been called\n");
		return NULL;
	}
	
	return pathappend(cache_dir, key);
}

#define BOM "\xEF\xBB\xBF"
#define BOMLEN strlen(BOM)

char * cache_get(const char * key)
{

	char * fname = make_path(key);
	FILE * kf = fopen(fname, "r");
	char * v;
	off_t flen;
	flen = filesize(fname);
	free(fname);

	if(!kf) return NULL;
	
	v = malloc(flen+1);
	if (v) {
		fread(v, 1, flen, kf);
		v[flen] = 0;
	}
	
	fclose(kf);
	return v;
}

void   cache_put(const char * key, const char * val)
{
	char * fname = make_path(key);
	FILE * kf = fopen(fname, "w");
	free(fname);
	
	if(!kf) return;
	
//	fwrite(BOM, BOMLEN, 1, kf);
	fwrite(val, strlen(val), 1, kf);
	fclose(kf);
}
