#include "boxutils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

off_t filesize(const char * localpath)
{
	struct stat sb;					

	stat(localpath, &sb);
	return sb.st_size;
}

char *  pathappend(const char * one, const char * two)
{
	char * res = malloc(strlen(one)+strlen(two)+2);
	res[0]=0;
	sprintf(res, strcmp(one,"/") ? "%s/%s" : "%s%s", one, two);
	return res;
}
