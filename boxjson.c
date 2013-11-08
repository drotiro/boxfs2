#include "boxjson.h"
#include <string.h>
#include <stdio.h>

time_t unix_time(const char * timestr)
{
	struct tm time;
	
	strptime(timestr, "%FT%T%z", &time);
	return mktime(&time);
}

/* predeclaration */
jobj *  jobj_new();

jobj * jobj_get(const jobj * obj, const char * key)
{
	list_iter it;

	if(obj->type == T_VAL) return NULL;

	it = list_get_iter(obj->children);
        jobj * item;

        for(; it; it = list_iter_next(it)) {
		item = list_iter_getval(it);
		if(!strcmp(item->key, key)) return item;
	}

        return NULL;
}

char * jobj_getval(const jobj * obj, const char * key)
{
        jobj * o = jobj_get(obj, key);
        if(o && o->value) return strdup(o->value);
        
        return NULL;
}

long long jobj_getlong(const jobj * obj, const char * key)
{
        jobj * o = jobj_get(obj, key);
        if(o && o->value) return atoll(o->value);
        
        return -1; // had to choose a value...
}

time_t jobj_gettime(const jobj * obj, const char * key)
{
	jobj * o = jobj_get(obj, key);
	if(o && o->value) {
	        return unix_time(o->value);
	}
        
	return (time_t)-1;
}

/*
 * Helpers for dom_callback, used by jobj_parse to
 * build a dom-like tree
 */

void * dom_mknode(int nesting, int is_object)
{
	jobj * o = jobj_new();
	o->type = (is_object ? T_OBJ : T_ARR);
	o->children = list_new();
	//printf("%s (%d)\n", is_object ? "object" : "array", nesting);
	return o;
}

void * dom_mkval(int type, const char *data, uint32_t length)
{
	jobj * o = jobj_new();
	o->type = T_VAL;
	//printf("#%s#\n", data);
	if(length) o->value = strndup(data, length);
	return o;
}

int dom_append(void *structure, char *key, uint32_t key_length, void *obj)
{
	jobj * parent = structure, * child = obj;
        
	//printf(" append\n");
	if(parent && child) {
		if(key_length) child->key = strndup(key, key_length);
		list_append(parent->children, child);
	}
	return 0;
}

jobj * jobj_array_item(const jobj * obj, int at)
{
	list_iter it;
	int i;
	if(obj->type != T_ARR) return NULL;
	if(at >= list_size(obj->children)) return NULL;
	
	it = list_get_iter(obj->children);
	for(i=0; i<at; ++i) it = list_iter_next(it);
	
	return (jobj*) list_iter_getval(it);
}

jobj * jobj_parse(const char * json_str)
{
	int res;
	jobj * o = NULL;
	json_parser_dom dom;
	json_parser p;
	json_config config;

	memset(&config, 0, sizeof(json_config));

	res = json_parser_dom_init(&dom, dom_mknode, dom_mkval, dom_append);
	if(res) return NULL;
	res = json_parser_init(&p, &config, json_parser_dom_callback, &dom);
	if(res) return NULL;

	res = json_parser_string(&p, json_str, strlen(json_str), NULL);
	if(!res && json_parser_is_done(&p)) o = dom.root_structure;
	
	json_parser_free(&p);
	json_parser_dom_free(&dom);
	return o;	
}

void jobj_free(jobj * obj)
{
	list_iter it;

	if(obj->type == T_VAL) {
		free(obj->value);
		return;
	}

	it = list_get_iter(obj->children);
	for(; it; it = list_iter_next(it)) {
		jobj_free(list_iter_getval(it));
	}
	if(obj->children) list_free(obj->children);
	free(obj);
}

jobj *  jobj_new()
{
        jobj * o = malloc(sizeof(jobj));
        memset(o, 0, sizeof(jobj));
        
        return o;
}

/*
void main(int argc, char **argv)
{
	jobj * o, *ic;
	#include "../../download/folder.json.c"
	//printf("Parsing json:\n%s\n-------\n\n", j);
	o = jobj_parse(j);
	if(o) {
	        list_iter dirs;
		
		printf("name = '%s'\n", jobj_get(o, "name")->value);
		ic = jobj_get(o, "item_collection");
		printf("total count = '%s'\n", jobj_get(ic, "total_count")->value);
		ic = jobj_get(ic, "entries");
		
		dirs = list_get_iter(ic->children);
		for(; dirs; dirs = list_iter_next(dirs)) {
		        printf(" dir: %s\n", 
		                jobj_get(list_iter_getval(dirs), "name")->value);
		}
		
		jobj_free(o);
	}
}
*/
