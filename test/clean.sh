#!/bin/sh

for name in client proxy ca repo
do
    if [ -d ${name} ] ; then
        rm ${name}/*.crt
        rm ${name}/*.key 
        rm ${name}/*.csr
    fi
done
