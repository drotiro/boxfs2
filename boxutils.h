#ifndef BOXUTILS_H
#define BOXUTILS_H

#include <sys/stat.h>
#include <stdio.h>

typedef struct edata_t {
	char * data;
	size_t len;
	size_t capacity;
} edata;

void    edata_init(edata * e);
void    edata_cat(edata * e, char * txt, size_t size);

off_t   filesize(const char * localpath);
char *  pathappend(const char * one, const char * two);      

#endif
//BOXUTILS_H