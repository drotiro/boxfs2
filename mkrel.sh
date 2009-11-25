#!/bin/bash

if [ $# -ne 1 ] ; then echo "usage $0 relno."; exit 1; fi;

TARGET=boxfs-$1

mkdir ../$TARGET
cp *.[ch] [CRM]* ../$TARGET
cd ..
tar czvf $TARGET.tgz $TARGET

