#!/bin/sh

workdir=R
PATH="../..:$PATH"

if [ ! -d $workdir ] ; then
    mkdir $workdir
fi

cd $workdir

kmtii_r.py \
    --untrust \
    --my-cert $HOME/work/lang/python/cert/server-cert.pem \
    --bind-port 41889 \
    $*
