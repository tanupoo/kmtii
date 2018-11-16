#!/bin/sh

workdir=C
PATH="../..:$PATH"

if [ ! -d $workdir ] ; then
    mkdir $workdir
fi

cd $workdir

kmtii_c.py \
    127.0.0.1 \
    --untrust \
    --server-url https://127.0.0.1:41887/csr \
    $*
