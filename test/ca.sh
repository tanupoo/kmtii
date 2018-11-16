#!/bin/sh

workdir=CA
PATH="../..:$PATH"

if [ ! -d $workdir ] ; then
    mkdir $workdir
fi

cd $workdir

kmtii_ca.py \
    --untrust \
    --ra-url https://127.0.0.1:41889/cert \
    --my-cert $HOME/work/lang/python/cert/server-cert.pem \
    --bind-port 41888 \
    $*
