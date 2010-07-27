#ifndef BOXOPTS_H
#define BOXOPTS_H

/* 2010-02-04 Domenico Rotiroti
   Licensed under the GPLv2

   Config file parsing and command line options
*/

/* command-line options */
typedef struct box_options_t
{
    char* user;
    char* password;
    char* mountpoint;
    int	verbose;
    int	secure;
} box_options;

extern box_options options;

int parse_options (int* argc, char*** argv, box_options * options);

#endif
//BOXOPTS_H
