#include "boxutils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define DATABUF 32768

off_t filesize(const char * localpath)
{
	struct stat sb;
	int sres;

	sres = stat(localpath, &sb);
	if(sres) return 0;
	return sb.st_size;
}

char *  pathappend(const char * one, const char * two)
{
	char * res = malloc(strlen(one)+strlen(two)+2);
	res[0]=0;
	sprintf(res, strcmp(one,"/") ? "%s/%s" : "%s%s", one, two);
	return res;
}

void edata_init(edata * e) {
	e->data = malloc(DATABUF);
	e->data[0] = 0;
	e->capacity = DATABUF;
	e->len = 0;
}

void edata_cat(edata * e, char * txt, size_t size)
{
	if((e->len+size) >= e->capacity) {
		//printf("old size: %d, new size: %d\n", e->capacity, e->capacity+DATABUF);
		e->data = realloc(e->data, e->capacity+DATABUF);
		e->capacity+=DATABUF;
	}
	
	memcpy(e->data+e->len, txt, size);
	e->len+=size;
	e->data[e->len] = 0;
}
