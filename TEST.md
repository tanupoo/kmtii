

## example

     C: 127.0.0.1
     S: https://127.0.0.1:41887
    CA: https://127.0.0.1:41888
     R: https://127.0.0.1:41889

    cd C
    python ../kmtii_c.py 127.0.0.1 --untrust --server-url https://127.0.0.1:41887/csr -vd

    cd S
    python ../kmtii_p.py --untrust --ca-url https://127.0.0.1:41888/csr --ra-url https://127.0.0.1:41889 --my-cert $HOME/work/lang/python/cert/server-cert.pem --bind-port 41887 -vd 

    cd CA
    python ../kmtii_ca.py --untrust --ra-url https://127.0.0.1:41889/cert --my-cert $HOME/work/lang/python/cert/server-cert.pem --bind-port 41888 -vd

    cd R
    python ../kmtii_ra.py --untrust --my-cert $HOME/work/lang/python/cert/server-cert.pem --bind-port 41889 -vd

