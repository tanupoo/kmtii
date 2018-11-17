TEST
====

## how to test

- change test directory.

    cd test

- execute prepare.sh. the 1st argument is the path to python. the 2nd argument is the full path to the package directory.

    sh prepare.sh /usr/bin/python3 /opt/pkg/kmtii

- open four terminals.
- change test directory on each terminal.
- execute below 4 script on each terminal.

    + client.sh
    + proxy.sh
    + ca.sh
    + repo.sh

- if you want to see the debug messages, just add -dv to the shell scripts.

- if you execute clean.sh, it will clean the files of crt, key, and csr.

## test topology

     C: 127.0.0.1

     S: https://127.0.0.1:41887

    CA: https://127.0.0.1:41888

     R: https://127.0.0.1:41889


