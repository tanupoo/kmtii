#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import sys
import argparse
import json
from hashlib import sha256
from datetime import datetime
from OpenSSL import crypto
import base64
import requests
from time import sleep
import os
from kmtii_util import *

requests.packages.urllib3.disable_warnings()

def parse_args():
    ap = argparse.ArgumentParser(
            description="""a client implementation
            for the ip address certification.""",
            epilog="still in progress.",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("client_addr",
                    help="specify the client's address.")
    ap.add_argument("--server-url", action="store", dest="server_url",
                    help="specify the URL to post CSR.")
    ap.add_argument("--key-size", action="store", dest="key_size",
                    type=int, default=2048,
                    help="specify the putlic key size.")
    ap.add_argument("--untrust", action="store_false", dest="trust_server",
                    help="disable to check the server certificate.")
    ap.add_argument("-v", action="store_true", dest="verbose",
                    help="enable verbose mode.")
    ap.add_argument("-d", action="store_true", dest="enable_debug",
                    help="enable debug mode.")
    opt = ap.parse_args()
    return opt, ap.print_help

def make_session_name(opt):
    # create the session name.
    m = sha256()
    m.update(opt.client_addr.encode())
    m.update(str(datetime.now()).encode())
    return m.hexdigest()

def get_csr(session_name, opt):
    # create CSR.
    csr = crypto.X509Req()
    subject = csr.get_subject()
    # XXX what is the name of the client ?
    #subject.C = b"JP"
    #subject.ST = b"Tokyo"
    #subject.O = b"JPNIC"
    #subject.OU = b"Engineering"
    subject.CN = session_name.encode()

    # add extensions
    x509_extensions = []

    # XXX what is the constraints, extensions ?
    '''
    # base_constraints
    x509_extensions.extend([
        crypto.X509Extension("basicConstraints", True, "CA:TRUE, pathlen:0"),
        crypto.X509Extension("extendedKeyUsage", True,
                            "serverAuth,emailProtection,timeStamping"),
        crypto.X509Extension("keyUsage", False, "keyCertSign, cRLSign"),
        crypto.X509Extension("subjectKeyIdentifier", False, "hash", subject=ca),
        ])
    '''

    '''
    # SubjectAltName
        e.g.
        DNS: hoge.example.com
        IP: 192.168.0.2
    '''
    sans_list = [
        "IP: {}".format(opt.client_addr).encode()
    ]
    x509_extensions.append(
            crypto.X509Extension(type_name=b"subjectAltName",
                                critical=False,
                                value=b", ".join(sans_list)))

    csr.add_extensions(x509_extensions)

    # generate a key pair and sign to CSR.
    pkey = crypto.PKey()
    pkey.generate_key(crypto.TYPE_RSA, opt.key_size)

    csr.set_pubkey(pkey)
    csr.sign(pkey, "sha256")

    # save csr and key.
    csr_pem = crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr)
    pkey_pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, pkey)

    return csr_pem, pkey_pem

def post_csr(csr_pem, session_name, opt):
    '''
    post CSR to S.
    get the access url and lead time.
    '''
    http_body = json.dumps({
            "csr": base64.b64encode(csr_pem).decode("utf-8"),
            "session_name": session_name,
            })
    debug(http_body, opt.enable_debug)

    http_header = {}
    http_header["Content-Type"] = "application/json"
    http_header["Accept"] = "application/json"

    try:
        res = requests.request("POST", opt.server_url, headers=http_header,
                            data=http_body, verify=opt.trust_server)
    except Exception as e:
        error("requests POST failed. {}".format(e))

    debug_http_post(res, opt.enable_debug)

    if res.ok:
        res_json = res.json()
        debug("{} {}".format(res.status_code, res.reason), opt.enable_debug)
        debug(res_json, opt.enable_debug)
        if res.headers["content-type"] == "application/json":
            access_url = res_json["access_url"]
            lead_time = int(res_json["lead_time"])
            return access_url, lead_time
        else:
            error("HTTP response from the server must be json.  {}".
                    format(res.text))
    else:
        error("HTTP response {} {}\n{}".format(
                res.status_code, res.reason, res.text))

def get_cert(access_url, session_name):
    http_body = json.dumps({
            "session_name": session_name,
            })
    debug(http_body, opt.enable_debug)

    http_header = {}
    http_header["Content-Type"] = "application/json"
    http_header["Accept"] = "application/json"

    try:
        res = requests.request("POST", access_url, headers=http_header,
                            data=http_body, verify=opt.trust_server)
    except Exception as e:
        error("requests POST failed. {}".format(e))

    debug_http_post(res, opt.enable_debug)

    if res.ok:
        res_json = res.json()
        debug("{} {}".format(res.status_code, res.reason), opt.enable_debug)
        debug(res_json, opt.enable_debug)
        if res.headers["content-type"] == "application/json":
            cert_pem = base64.b64decode(res_json["cert"])
            return cert_pem
        else:
            error("HTTP response from the server must be json.  {}".
                    format(res.text))
    else:
        error("HTTP response {} {}\n{}".format(
                res.status_code, res.reason, res.text))

def do_session(csr_pem, pkey_pem, session_name, opt):

    # post CSR to S
    debug("submitting CSR to {}".format(opt.server_url), opt.enable_debug)
    access_url, lead_time = post_csr(csr_pem, session_name, opt)
    if access_url is None:
        error("getting access url failed.")

    debug("waiting in {} seconds for the certificate creation.".
          format(lead_time), opt.enable_debug)
    sleep(lead_time)

    debug("accessing to {}".format(access_url), opt.enable_debug)
    cert_pem = get_cert(access_url, session_name)
    if cert_pem is None:
        error("getting certificate failed.")
    with open(session_name+".crt", 'wb+') as fd:
        fd.write(cert_pem)

    debug("successful to get my certificate.", opt.enable_debug)

#
# main
#
opt, print_help = parse_args()
session_name = make_session_name(opt)

# create CSR and Key pair.
debug("creating CSR", opt.enable_debug)
csr_pem, pkey_pem = get_csr(session_name, opt)
debug("CSR: {}".format(csr_pem), opt.enable_debug)
if csr_pem is None or pkey_pem is None:
    error("getting CSR failed.")

csr_file = session_name + ".csr"
pkey_file = session_name + ".key"

with open(csr_file, "wb+") as fd:
    fd.write(csr_pem)
with open(pkey_file, 'wb+') as fd:
    fd.write(pkey_pem)

try:
    do_session(csr_pem, pkey_pem, session_name, opt)
except KeyboardInterrupt:
    os.remove(csr_file)
    os.remove(pkey_file)

