#ifndef BOXUTILS_H
#define BOXUTILS_H

#include <sys/stat.h>

off_t   filesize(const char * localpath);
char *  pathappend(const char * one, const char * two);      

#endif
//BOXUTILS_H