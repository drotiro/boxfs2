#ifndef BOXOPTS_H
#define BOXOPTS_H

/* 2010-02-04 Domenico Rotiroti
   Licensed under the GPLv2

   Config file parsing and command line options
*/

#include <sys/stat.h>

/* command-line options */
typedef struct box_options_t
{
    char* user;
    char* password;
    char* mountpoint;
    uid_t uid;
    gid_t gid;
    mode_t fperm;
    mode_t dperm;
    int	verbose;
    int	secure;
    int splitfiles;
} box_options;

extern box_options options;

int parse_options (int* argc, char*** argv, box_options * options);

#endif
//BOXOPTS_H
