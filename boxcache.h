#ifndef BOXCACHE_H
#define BOXCACHE_H

void   cache_init(const char * path);

char * cache_get(const char * key);
void   cache_put(const char * key, const char * val);
void   cache_rm(const char * key);

#endif
//BOXCACHE_H