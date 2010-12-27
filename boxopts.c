/**************************
 Licensed under the GPLv2
 **************************/

#include "boxopts.h"
#include <string.h>
#include <libapp/app.h>
#include <stdio.h>
#include <stdlib.h>
#include <fuse.h>

char* args[] = { "boxfs", "-h" };

void show_fuse_usage (app * theapp, const char * opt)
{
    fuse_main (2, args, NULL);
}

void show_usage (app * this, const char * opt)
{
    printf ("Usage: boxfs [options] [mountPoint] [FUSE Mount Options]\n\n"
            "Options:\n"
            "  -H                          show optional FUSE mount options\n"
            "  -u --username   login       box.net login name\n"
            "  -p --password   password    box.net password\n"
            "  -f              conffile    file containing configuration options\n"
            "  -l --largefiles             enable support for large files (splitting)\n"
            "  -v --verbose                turn on verbose syslogging\n"
            "  -s --secure                 turn on secure connections (HTTPS) to box.net\n\n"
            "Configuration file example:\n"
            "username   = mymail@mydomain.com\n"
            "mountpoint = /path/to/folder\n"
            "verbose    = no\n"
            "secure     = no\n"
            "password = secret\n\n");
}

int parse_options (int* argc, char*** argv, box_options * options)
{
    char* pass_file = NULL;
    app * this;
    bool res;
    FILE * cfile;
    opt optdef[] = {
		{'H', NULL, OPT_CALLBACK, &show_fuse_usage},
		{'u', "username", OPT_STRING, &options->user},
		{'p', "password", OPT_PASSWD, &options->password},
		{'f', NULL, OPT_STRING, &pass_file},
		{'v', "verbose", OPT_FLAG, &options->verbose},
		{'s', "secure", OPT_FLAG, &options->secure},
                {'l', "largefiles", OPT_FLAG, &options->splitfiles},
		{0, "mountpoint", OPT_STRING, &options->mountpoint}
	};

    memset(options, 0, sizeof(options));
    this = app_new();
    app_opts_add(this, optdef, 8);
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

    /* check for mountpoint presence */
    if(res && !options->mountpoint && !*argc) {
    	fprintf(stderr, "Error: mountpoint not specified\n"
			"You should pass it on the command line or in the config file.\n");
		res = false;
		show_usage(this, "mountpoint");
	}
	
	if(res) {
		if(!options->user) {
			printf("Login: ");
			options->user = app_term_readline();
		}
		
		if(!options->password) {
			options->password = app_term_askpass("Password:");
		}

		args[1] = options->mountpoint ? options->mountpoint : *argv[0];
		*argc = 2;
		*argv = args;
	}	

	app_free(this);
    return (res ? 0 : 1);
}
