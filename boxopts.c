/**************************
 Licensed under the GPLv2
 **************************/

#include "boxapi.h"
#include "boxopts.h"
#include <string.h>
#include <libapp/app.h>
#include <stdio.h>
#include <stdlib.h>
#include <fuse.h>

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

void show_usage (app * this, const char * opt)
{
    printf ("Usage: boxfs [options] [mountPoint]\n\n"
            "Options:\n"
//            "  -H                          show optional FUSE mount options\n"
//            "  -u --username   login       box.net login name\n"
//            "  -p --password   password    box.net password\n"
            "  -f              conffile    file containing configuration options\n"
	    "  -t --token_file tokenfile   file containing oauth tokens\n"
            "  -l --largefiles             enable support for large files (splitting)\n"
            "  -v --verbose                turn on verbose syslogging\n"
            "  -U --uid                    user id to use as file owner (defaults to you)\n"
            "  -G --gid                    group id to use for group permissions\n"
            "  -F --fperm                  file permissions (default 0644)\n"
            "  -D --dperm                  directory permissions (default 0755)\n\n"
            "Configuration file example:\n"
            "mountpoint = /path/to/folder\n"
            "verbose    = no\n"
            "token_file = /path/to/token_file\n"
            "cache_dir  = /path/to/cache/dir\n"
            "largefiles = no\n"
            "uid = 1000\n"
            "gid = 100\n"
            "fperm = 644\n"
            "dperm = 755\n\n");
}

int parse_options (int* argc, char*** argv, box_options * options)
{
    char* pass_file = NULL;
    app * this;
    bool res;
    FILE * cfile, * tfile;
    opt opts[] = {
/* FUSE options are not handled at the moment, so let's disable -H */
//		{'H', NULL, OPT_CALLBACK, &show_fuse_usage},
//		{'u', "username", OPT_STRING, &options->user},
//		{'p', "password", OPT_PASSWD, &options->password},
	    	{'t', "token_file", OPT_STRING, &options->token_file},
	    	{'c', "cache_dir", OPT_STRING, &options->cache_dir},
		{'f', NULL, OPT_STRING, &pass_file},
		{'v', "verbose", OPT_FLAG, &options->verbose},
//		{'s', "secure", OPT_FLAG, &options->secure},
                {'l', "largefiles", OPT_FLAG, &options->splitfiles},
                {'U', "uid", OPT_INT, &options->uid},
                {'G', "gid", OPT_INT, &options->gid},
                {'F', "fperm", OPT_INT, &options->fperm},
                {'D', "dperm", OPT_INT, &options->dperm},
		{0, "mountpoint", OPT_STRING, &options->mountpoint}
	};

    memset(options, 0, sizeof(options));
    options->uid = getuid();
    options->gid = getgid();
    this = app_new();
    app_opts_add(this, opts, sizeof(opts)/sizeof(opts[0]));
    app_opt_on_error(this, &show_usage);
    res = app_parse_opts(this, argc, argv);

    if (res && pass_file) {
    	cfile = fopen(pass_file, "r");
		if(cfile) {
			res = app_parse_opts_from(this, cfile);
			fclose(cfile);
		} else {
			fprintf(stderr, "Error: cannot open config file %s\n", pass_file);
			res = false;
			show_usage(this, "f");
		}
    }

    if(res && options->token_file) {
	tfile = fopen(options->token_file, "r");
	if(tfile) {
		auth_token    = app_term_readline_from(tfile);
		auth_token[strlen(auth_token)-1] = 0; //trim
		refresh_token = app_term_readline_from(tfile);
		refresh_token[strlen(refresh_token)-1] = 0; //trim
		fclose(tfile);
	} else {
		fprintf(stderr, "Info: will write auth tokens in file %s\n", options->token_file);
	}
    }

    /* check for mountpoint presence */
    if(res && !options->mountpoint && !*argc) {
    	fprintf(stderr, "Error: mountpoint not specified\n"
			"You should pass it on the command line or in the config file.\n");
		res = false;
		show_usage(this, "mountpoint");
	}
	
	if(res) {
		/*
		if(!options->user) {
			printf("Login: ");
			options->user = app_term_readline();
		}
		
		if(!options->password) {
			options->password = app_term_askpass("Password:");
		}
		*/
		if(!options->dperm)
			options->dperm = 0755;
		else
			options->dperm = itomode(options->dperm);
		if(!options->fperm)
			options->fperm = 0644;
		else
			options->fperm = itomode(options->fperm);
		if(!options->mountpoint) options->mountpoint = *argv[0];
		args[1] = options->mountpoint;
		*argc = 2;
		*argv = args;
	}	

	app_free(this);
    return (res ? 0 : 1);
}
