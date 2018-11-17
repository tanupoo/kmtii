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
import logging
from kmtii_util import *

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
    subject.CN = session_name.encode()

    # XXX the client's ip address should be set into SAN for RA's check ?
    # XXX currently, the address is set for sure.
    sans_list = [
	"IP: {}".format(opt.client_addr).encode()
    ]
    x509_ext = []
    x509_ext.append(
            crypto.X509Extension(type_name=b"subjectAltName",
                                 critical=False,
                                 value=b", ".join(sans_list)))
    csr.add_extensions(x509_ext)

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
    logger.debug(http_body)

    http_header = {}
    http_header["Content-Type"] = "application/json"
    http_header["Accept"] = "application/json"

    try:
        res = requests.request("POST", opt.server_url, headers=http_header,
                            data=http_body, verify=opt.trust_server)
    except Exception as e:
        logger.error("requests POST failed. {}".format(e))
        return None, None

    debug_http_post(res, logger)

    if not res.ok:
        logger.error("HTTP response {} {}\n{}".format(
                res.status_code, res.reason, res.text))
        return None, None

    res_json = res.json()
    logger.debug("{} {}".format(res.status_code, res.reason))
    logger.debug(res_json)

    if res.headers["content-type"] != "application/json":
        logger.error("HTTP response from the server must be json.  {}".
                format(res.text))
        return None, None

    access_url = res_json["access_url"]
    lead_time = int(res_json["lead_time"])
    return access_url, lead_time

def get_cert(access_url, session_name):
    http_body = json.dumps({
            "session_name": session_name,
            })
    logger.debug(http_body)

    http_header = {}
    http_header["Content-Type"] = "application/json"
    http_header["Accept"] = "application/json"

    try:
        res = requests.request("POST", access_url, headers=http_header,
                            data=http_body, verify=opt.trust_server)
    except Exception as e:
        logger.error("requests POST failed. {}".format(e))
        return None

    debug_http_post(res, logger)

    if not res.ok:
        logger.error("HTTP response {} {}\n{}".format(
                res.status_code, res.reason, res.text))
        return None

    res_json = res.json()
    logger.debug("{} {}".format(res.status_code, res.reason))
    logger.debug(res_json)
    if res.headers["content-type"] != "application/json":
        logger.error("HTTP response from the server must be json.  {}".
                format(res.text))
        return None

    cert_pem = base64.b64decode(res_json["cert"])
    return cert_pem

def do_session(csr_pem, pkey_pem, session_name, opt):

    # post CSR to S
    logger.debug("submitting CSR to {}".format(opt.server_url))
    access_url, lead_time = post_csr(csr_pem, session_name, opt)
    if access_url is None:
        logger.error("getting access url failed.")
        return None

    logger.debug("waiting in {} seconds for the certificate creation.".
          format(lead_time))
    sleep(lead_time)

    logger.debug("accessing to {}".format(access_url))
    cert_pem = get_cert(access_url, session_name)
    if cert_pem is None:
        logger.error("getting certificate failed.")
        return None

    return cert_pem

#
# main
#
opt, print_help = parse_args()
logger = set_logger(logging, opt.enable_debug)
if not opt.enable_debug:
    requests.packages.urllib3.disable_warnings()

#
session_name = make_session_name(opt)

# create CSR and Key pair.
logger.debug("creating CSR")
csr_pem, pkey_pem = get_csr(session_name, opt)
logger.debug("CSR: {}".format(csr_pem))
if csr_pem is None or pkey_pem is None:
    logger.error("getting CSR failed.")
    exit(1)

csr_file = session_name + ".csr"
pkey_file = session_name + ".key"

with open(csr_file, "wb+") as fd:
    fd.write(csr_pem)
with open(pkey_file, 'wb+') as fd:
    fd.write(pkey_pem)

cert_pem = None
try:
    cert_pem = do_session(csr_pem, pkey_pem, session_name, opt)
except KeyboardInterrupt:
    os.remove(csr_file)
    os.remove(pkey_file)
    exit(1)

if cert_pem is not None:
    exit(1)

with open(session_name+".crt", 'wb+') as fd:
    fd.write(cert_pem)

logger.info("successful to get my certificate.")

