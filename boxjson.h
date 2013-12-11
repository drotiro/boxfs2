#ifndef BOXJSON_H
#define BOXJSON_H

/* 2013-10-18 Domenico Rotiroti
 *    Licensed under the GPLv3
 *
 *    JSON parsing and traversing
 *    functions.
 */
 
#define _XOPEN_SOURCE 700
#include <json.h>
#include <libapp/list.h>
#include <time.h>


typedef enum { T_VAL, T_OBJ, T_ARR } objtype;

typedef struct jobj_t {
	char *  key;
	objtype type;
	char *  value;
	list *  children;
	
} jobj;

/*
 * Get child nodes, searching by key or by position
 */
jobj *    jobj_get(const jobj * obj, const char * key);
char *    jobj_getval(const jobj * obj, const char * key);
long long jobj_getlong(const jobj * obj, const char * key);
time_t    jobj_gettime(const jobj * obj, const char * key);
jobj *    jobj_array_item(const jobj * obj, int at);

/*
 * Create and destroy methods
 */
jobj *  jobj_parse(const char * json_str);
void    jobj_free(jobj * obj);

time_t  unix_time(const char * timestr);
#endif
//BOXJSON_H
