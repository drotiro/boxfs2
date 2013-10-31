#ifndef BOXOPTS_H
#define BOXOPTS_H

/* 2010-02-04 Domenico Rotiroti
   Licensed under the GPLv3

   Config file parsing and command line options
*/

#include <sys/stat.h>

/* command-line options */
typedef struct box_options_t
{
    char* token_file;
    char* cache_dir;
    char* mountpoint;
    uid_t uid;
    gid_t gid;
    mode_t fperm;
    mode_t dperm;
    int	verbose;
    int splitfiles;
    int expire_time;
} box_options;

extern box_options options;

int parse_options (int* argc, char*** argv, box_options * options);

#endif
//BOXOPTS_H
