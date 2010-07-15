/**************************
 Licensed under the GPLv2
 **************************/

#include "boxopts.h"
#include <string.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

/* some constant */
static const char KEY_USER [] = "username";
static const char KEY_PASS [] = "password";
static const char KEY_MOUNT [] = "mountpoint";
static const char KEY_VERBOSE [] = "verbose";
static const char KEY_SECURE [] = "secure";
static const char SEP [] = "=";
static const char VAL_YES [] = "yes";
static const char VAL_NO [] = "no";


void show_usage ()
{
    printf ("Usage: boxfs [options] [mountPoint] [FUSE Mount Options]\n\n"
            "Options:\n"
            "  -H                show optional FUSE mount options\n"
            "  -u login          box.net login name\n"
            "  -p password       box.net password\n"
            "  -f conffile       file containing configuration options\n"
            "  -v                turn on verbose syslogging\n"
            "  -s                turn on secure connections (HTTPS) to box.net\n\n"
            "Configuration file example:\n"
            "username   = mymail@mydomain.com\n"
            "mountpoint = /path/to/folder\n"
            "verbose    = no"
            "secure     = no"
            "password = secret\n\n");
}

void show_fuse_usage ()
{
    int argc = 2;
    char* argv[] = { "boxfs", "-h" };

    fuse_main (argc, argv, NULL);
}


void wipeopt(char * opt) 
{
	memset(opt, 0, strlen(opt));
}


int parse_options (int* argc, char*** argv, box_options * options)
{
    int c;
    char* pass_file = NULL;

    options->user = NULL;
    options->password = NULL;
    options->mountpoint = NULL;
    options->verbose = 0;
    options->secure = 0;

    while ((c = getopt (*argc, *argv, "Hhu:p:f:vs")) != -1) {
        switch (c) {
        case 'H':
            show_fuse_usage ();
            return 1;
        case 'h':
            show_usage ();
            return 1;
        case 'u':
            options->user = strdup (optarg);
            break;
        case 'p':
            options->password = strdup (optarg);
			wipeopt(optarg);
            break;
        case 'f':
            pass_file = optarg;
            break;
        case 'v':
            options->verbose = 1;
            break;
        case 's':
            options->secure = 1;
            break;
        case '?':
            if (optopt == 'u' || optopt == 'p' || optopt == 'f')
                printf ("Option -%c requires an argument.\n", optopt);
            return 1;
        }
    }

    if (pass_file) {
        if (read_conf_file (pass_file, options)) {
            show_usage();
            return 1;
        }
    }

    /* check for mountpoint presence */
    if (optind == *argc) {
        if(options->mountpoint) {
            optind--;
            (*argv)[optind] = strdup(options->mountpoint);
        } else {
            printf("Error: mountpoint not specified\n"
                "You should pass it on the command line or in the config file.\n");
            return 1;
        }
    }

    *argc -= optind - 1;
    *argv += optind - 1;

    return 0;
}

void free_options (box_options * options)
{
    if (options->user)
        free (options->user);
    if (options->password)
        free (options->password);
    if (options->mountpoint)
        free(options->mountpoint);
}

void trim(char *s) {
	if (!s) return;
    char *p = s;
    int l = strlen(p);

    while(isspace(p[l - 1])) p[--l] = 0;
    while(* p && isspace(* p)) ++p, --l;

    memmove(s, p, l + 1);
}

int parse_yesno(const char * opt, const char * val)
{
    if(!strcmp(val,VAL_YES)) return 1;
    if(!strcmp(val,VAL_NO)) return 0;
    fprintf(stderr, "Invalid value %s for option %s (use '%s' or '%s')\n\n",
        val, opt, VAL_YES, VAL_NO);
    return -1;
}

int read_conf_file (const char* file_name, box_options* options)
{
    FILE *f;
    int res = 0, nline = 0;
    char *optkey=NULL, *optval = NULL, line[1024]="";
    const char KEY_USER [] = "username";
    const char KEY_PASS [] = "password";
    const char KEY_MOUNT [] = "mountpoint";
    const char KEY_VERBOSE [] = "verbose";
    const char KEY_SECURE [] = "secure";
    const char SEP [] = "=";

    if ((f = fopen(file_name, "r")) == NULL) {
        fprintf(stderr, "cannot open %s\n", file_name);
        return 1;
    }
	//bzero(options, sizeof(box_options));
	
    do {
	++nline;
        if (fgets(line, sizeof(line), f)==NULL) break;
	trim(line);
        if(*line=='#' || strlen(line) == 0) continue; // skip comments
		
        optkey = strtok(line,SEP);
        optval = strtok(NULL,SEP);
        if(optkey == NULL || optval == NULL) {
            fprintf(stderr, "Invalid line #%d in configuration file %s\n\n", 
              nline, file_name);
            res = 1;
            break;
        }
        trim(optkey);
	trim(optval);

        if (!strcmp(optkey,KEY_USER)) options->user = strdup(optval);
        else if (!strcmp(optkey,KEY_PASS)) options->password = strdup(optval);
        else if (!strcmp(optkey,KEY_MOUNT)) options->mountpoint = strdup(optval);
        else if (!strcmp(optkey,KEY_VERBOSE)) {
            options->verbose = parse_yesno(optkey, optval);
            if(options->verbose < 0) { res = 1; break; }
        }
        else if (!strcmp(optkey,KEY_SECURE)) {
            options->secure = parse_yesno(optkey, optval);
            if(options->secure < 0) { res = 1; break; }
        }
        else { 
            fprintf(stderr,"Invalid option %s in file %s (line #%d)\n", optkey, file_name, nline);
            res = 1;
            break;
        }
    } while(!feof(f));
    fclose(f);

    return res;
};
