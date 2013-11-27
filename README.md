BOXFS
=====

A FUSE-based filesystem for box.com.

This software is licensed under the GPLv3 Licence and comes with NO WARRANTY.
Use at your own risk. See gpl-3.0.txt.

Boxfs use the v2 version of box.com api (see http://developers.box.com/docs/),
older versions used the v1 api.

Compiling
---------

 * Get the sources from GitHub: `git clone https://github.com/drotiro/boxfs2.git`
 * Make sure you have all the needed dependencies:
  * fuse
  * libcurl
  * libxml2
  * libapp  - https://github.com/drotiro/libapp
  * libjson - https://github.com/vincenthz/libjson/
 * Type `make` and then `sudo make install`

If you prefer a static build or don't want to install libapp and libjson system-wide,
you can run `make static` to: 
 * download (`git clone`) libapp and libjson, inside the boxfs source tree
 * compile them
 * link boxfs against those local libs

Usage
-----

Boxfs can read options from command line or from a config file.

The simplest way to start is to run the script `boxfs-init` and let it create
a configuration file for you.

The first time you run boxfs, you will need to complete the authentication
(oauth2) process and grant access to your box.com account. It's easy, just
follow the instructions on the terminal and on your browser.

The first mount can be quite slow because boxfs will fetch and cache info
(metadata, not file contents!) about your folders.

	Usage: boxfs [options] [mountPoint]
	
	Options:
	  -h                          shows this help message
	  -f               conffile   file containing configuration options
	  -t --token_file  tokenfile  file containing oauth tokens
	  -c --cache_dir   cachedir   directory used to cache metadata
	  -e --expire_time N          expire time for cache entries (in minutes)
	  -l --largefiles             enable support for large files (splitting)
	  -v --verbose                turn on verbose syslogging
	  -U --uid                    user id to use as file owner (defaults to you)
	  -G --gid                    group id to use for group permissions
	  -F --fperm                  file permissions (default 0644)
	  -D --dperm                  directory permissions (default 0755)


When you've done using your files, unmount your filsystem
with `fusermount -u mountpoint`

Authors and Contributors
========================

Boxfs is written by Domenico Rotiroti.
See README.V1 for a list of people who helped in the previous releases.

Known problems/limitations
==========================

 * Sharing, tags and other file metadata are not handled
 * Updates made from outside boxfs are not visible until remount
 * Can't create empty files
