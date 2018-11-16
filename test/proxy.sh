#!/bin/sh

workdir=P
PATH="../..:$PATH"

if [ ! -d $workdir ] ; then
    mkdir $workdir
fi

cd $workdir

kmtii_p.py \
    --untrust \
    --ca-url https://127.0.0.1:41888/csr \
    --ra-url https://127.0.0.1:41889 \
    --my-cert $HOME/work/lang/python/cert/server-cert.pem \
    --bind-port 41887 \
    $*
