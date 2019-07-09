/**************************
 Licensed under the GPLv3
 **************************/

#include "boxapi.h"
#include "boxopts.h"
#include <string.h>
#include <libapp/app.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

char* args[] = { "boxfs", "-h" };
/*
void show_fuse_usage (app * theapp, const char * opt)
{
    fuse_main (2, args, NULL);
}
*/

mode_t itomode (int mode)
{
    int ua;
    int ga;
    int oa;

    mode_t uam;
    mode_t gam;
    mode_t oam;

    if (mode >= 0 && mode <= 777) {
        oa = mode % 10;
        mode /= 10;
        ga = mode % 10;
        mode /= 10;
        ua = mode;
    } 
    else
    {
        return -1;
    }

    if (oa > 7 || ga > 7 || ua > 7)
    {
        return -1;
    }

    if (ua == 7) uam = S_IRWXU;
    else if (ua == 6) uam = S_IRUSR | S_IWUSR;
    else if (ua == 5) uam = S_IRUSR | S_IXUSR;
    else if (ua == 4) uam = S_IRUSR;
    else if (ua == 3) uam = S_IWUSR | S_IXUSR;
    else if (ua == 2) uam = S_IWUSR;
    else if (ua == 1) uam = S_IXUSR;
    else uam = 0;
    if (ga == 7) gam = S_IRWXG;
    else if (ga == 6) gam = S_IRGRP | S_IWGRP;
    else if (ga == 5) gam = S_IRGRP | S_IXGRP;
    else if (ga == 4) gam = S_IRGRP;
    else if (ga == 3) gam = S_IWGRP | S_IXGRP;
    else if (ga == 2) gam = S_IWGRP;
    else if (ga == 1) gam = S_IXGRP;
    else gam = 0;
    if (oa == 7) oam = S_IRWXO;
    else if (oa == 6) oam = S_IROTH | S_IWOTH;
    else if (oa == 5) oam = S_IROTH | S_IXOTH;
    else if (oa == 4) oam = S_IROTH;
    else if (oa == 3) oam = S_IWOTH | S_IXOTH;
    else if (oa == 2) oam = S_IWOTH;
    else if (oa == 1) oam = S_IXOTH;
    else oam = 0;

    return uam | gam | oam;
}

void show_error (app * this, const char * err)
{
        if(!strcmp(err, "config"))
                fprintf(stderr, "Error: cannot open config file\n");
        else if(!strcmp(err, "mountpoint"))
                fprintf(stderr, "Error: missing mount point\n"
			"You should pass it on the command line or in the config file.\n");

        fprintf(stderr, "\ntype 'boxfs -h' for help\n");
}

void show_help()
{
    printf ("Usage: boxfs [options] [mountPoint]\n\n"
            "Options:\n"
//            "  -H                          show optional FUSE mount options\n"
            "  -h                          shows this help message\n"
            "  -f               conffile   file containing configuration options\n"
	    "  -t --token_file  tokenfile  file containing oauth tokens\n"
	    "  -c --cache_dir   cachedir   directory used to cache metadata\n"
	    "  -e --expire_time N          expire time for cache entries (in minutes)\n"
            "  -l --largefiles             enable support for large files (splitting)\n"
            "  -v --verbose                turn on verbose syslogging\n"
            "  -U --uid                    user id to use as file owner (defaults to you)\n"
            "  -G --gid                    group id to use for group permissions\n"
            "  -F --fperm                  file permissions (default 0644)\n"
            "  -D --dperm                  directory permissions (default 0755)\n"
            "  -o --fuse_options           specify FUSE mount options\n\n"
            "Configuration file example:\n"
            "mountpoint = /path/to/folder\n"
            "verbose    = no\n"
            "token_file = /path/to/token_file\n"
            "cache_dir  = /path/to/cache/dir\n"
            "expire_time = 1440\n"
            "largefiles = no\n"
            "uid = 1000\n"
            "gid = 100\n"
            "fperm = 644\n"
            "dperm = 755\n"
            "fuse_options = allow_other,default_permissions\n\n");
            
            exit(0);
}

int parse_options (int* argc, char*** argv, box_options * options)
{
    char* pass_file = NULL;
    app * this;
    bool res;
    FILE * cfile, * tfile;
    opt opts[] = {
	    	{'t', "token_file", OPT_STRING, &options->token_file},
	    	{'c', "cache_dir", OPT_STRING, &options->cache_dir},
	    	{'e', "expire_time", OPT_INT, &options->expire_time},
		{'f', NULL, OPT_STRING, &pass_file},
		{'v', "verbose", OPT_FLAG, &options->verbose},
                {'l', "largefiles", OPT_FLAG, &options->splitfiles},
                {'U', "uid", OPT_INT, &options->uid},
                {'G', "gid", OPT_INT, &options->gid},
                {'F', "fperm", OPT_INT, &options->fperm},
                {'D', "dperm", OPT_INT, &options->dperm},
                {'o', "fuse_options", OPT_STRING, &options->fuse_options},
                {'h', NULL, OPT_CALLBACK, &show_help},
		{0, "mountpoint", OPT_STRING, &options->mountpoint}
	};

    memset(options, 0, sizeof(box_options));
    options->uid = getuid();
    options->gid = getgid();
    this = app_new();
    app_opts_add(this, opts, sizeof(opts)/sizeof(opts[0]));
    app_opt_on_error(this, &show_error);
    res = app_parse_opts(this, argc, argv);

    if (res && pass_file) {
    	cfile = fopen(pass_file, "r");
		if(cfile) {
			res = app_parse_opts_from(this, cfile);
			fclose(cfile);
		} else {
			res = false;
			show_error(this, "config");
		}
    }

    if(res && options->token_file) {
	tfile = fopen(options->token_file, "r");
	if(tfile) {
		auth_token    = app_term_readline_from(tfile);
		if(auth_token) auth_token[strlen(auth_token)-1] = 0; //trim
		refresh_token = app_term_readline_from(tfile);
		if(refresh_token) refresh_token[strlen(refresh_token)-1] = 0; //trim
		fclose(tfile);
	} else {
		fprintf(stderr, "Info: will write auth tokens in file %s\n", options->token_file);
	}
    }

    /* check for mountpoint presence */
    	if(res && !options->mountpoint && !*argc) {
		res = false;
		show_error(this, "mountpoint");
	}
	
	if(res) {
		if(!options->dperm)
			options->dperm = 0755;
		else
			options->dperm = itomode(options->dperm);
		if(!options->fperm)
			options->fperm = 0644;
		else
			options->fperm = itomode(options->fperm);
		if(!options->mountpoint)  {
			options->mountpoint = *argv[0];
			if(*argc > 1) {
				*argv+=1;
				*argc-=1;
			}
		}

		/* prefix the options with -o, such as "allow_other" to "-oallow_other"
		   since that is how `fuse_opt_add_arg` works in libfuse */
		if(options->fuse_options) {
		    char * fuse_option_prefix = "-o";
		    size_t fuse_options_length = strlen(fuse_option_prefix) + strlen(options->fuse_options) + 1;
		    char * tmp_fuse_options = (char *) malloc(fuse_options_length);
		    strcpy(tmp_fuse_options, fuse_option_prefix);
		    strcat(tmp_fuse_options, options->fuse_options);
		    options->fuse_options = tmp_fuse_options;
		}

		args[1] = options->mountpoint;
		args[2] = options->fuse_options;

		/* check for fuse options and build the new argv for fuse main */
		if(*argc) {
			char ** fargs = malloc( (*argc + 1) * sizeof(char*) );
			int i;
		        
			fargs[0] = args[0]; // "boxfs"
			fargs[1] = args[1]; // mountpoint
			fargs[2] = args[2]; // fuse_options

		        for(i = 1; i < *argc; ++i) fargs[i+1] = (*argv)[i];

		        *argc+=1;
		        *argv = fargs;
		} else {
        		*argc = 2;
        		*argv = args;
                }
	}	

	app_free(this);
	return (res ? 0 : 1);
}
