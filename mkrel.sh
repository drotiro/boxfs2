#!/bin/bash

if [ $# -ne 1 ] ; then echo "usage $0 relno."; exit 1; fi;

TARGET=../boxfs-$1

mkdir $TARGET
cp *.[ch] [CR]* $TARGET
cp Makefile.dist $TARGET/Makefile
cd ..
tar czvf boxfs-$1.tgz boxfs-$1

