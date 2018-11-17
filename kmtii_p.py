#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import sys
import argparse
import json
from hashlib import sha256
from datetime import datetime
import requests
from time import sleep
import threading
from bottle import route, run, request, response, ServerAdapter
from ssl import wrap_socket
from wsgiref.simple_server import make_server
from kmtii_util import *
import logging

lead_time = 10

def parse_args():
    ap = argparse.ArgumentParser(
            description="""a proxy server implementation
            for the ip address certification.""",
            epilog="still in progress.",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument("wan_addr",
                    help="specify the WAN address.")
    ap.add_argument("--ca-url", action="store", dest="ca_url", required=True,
                    help="specify the URL of CA to submit CSR.")
    ap.add_argument("--ra-url", action="store", dest="ra_url", required=True,
                    help="specify the URL of RA.")
    ap.add_argument("--bind-addr", action="store", dest="bind_addr",
                    default="0.0.0.0",
                    help="specify the address to be bound.")
    ap.add_argument("--bind-port", action="store", dest="bind_port",
                    type=int, default=41887,
                    help="specify the port number to be bound.")
    ap.add_argument("--my-cert", action="store", dest="my_cert", required=True,
                    help="specify the certificate of mine.")
    ap.add_argument("--untrust", action="store_false", dest="trust_server",
                    help="disable to check the server certificate.")
    ap.add_argument("--tx-count", action="store", dest="tx_count",
                    type=int, default=3,
                    help="specify the number of transmitting count.")
    ap.add_argument("--tx-interval", action="store", dest="tx_interval",
                    type=int, default=5,
                    help="specify the retransmit interval in seconds.")
    ap.add_argument("-v", action="store_true", dest="verbose",
                    help="enable verbose mode.")
    ap.add_argument("-d", action="store_true", dest="enable_debug",
                    help="enable debug mode.")
    opt = ap.parse_args()
    return opt, ap.print_help

def get_lead_time():
    # XXX in seconds. it should be taken from CA.
    global lead_time
    return lead_time

def make_access_url(session_name, client_addr, opt):
    # create the session name.
    m = sha256()
    m.update(client_addr.encode())
    m.update(str(datetime.now()).encode())
    return "{}/{}".format(opt.ra_url, m.hexdigest())

def post_csr(csr_pem_b, client_addr, access_url, session_name, opt):
    '''
    post CSR to CA.
    '''
    http_body = json.dumps({
            "csr": csr_pem_b,
            "client_addr": client_addr,
            "wan_addr": opt.wan_addr,
            "session_name": session_name,
            "access_url": access_url,
            })
    logger.debug(http_body)

    http_header = {}
    http_header["Content-Type"] = "application/json"
    http_header["Accept"] = "application/json"

    tx_count = opt.tx_count
    while tx_count > 0:
        tx_count -= 1
        try:
            res = requests.request("POST", opt.ca_url, headers=http_header,
                                data=http_body, verify=opt.trust_server)
            break
        except Exception as e:
            logger.error("accessing CA failed. {}".format(e))
            if tx_count == 0:
                return None, None
        sleep(opt.tx_interval)

    debug_http_post(res, logger)

    if not res.ok:
        logger.error("HTTP response {} {}\n{}".format(
                res.status_code, res.reason, res.text))
        return False

    logger.debug("{} {}".format(res.status_code, res.reason))
    return True

def worker(session_name, client_addr, csr_pem_b, access_url, opt):
    ret = post_csr(csr_pem_b, client_addr, access_url, session_name, opt)
    if ret != True:
        logger.error("sending CSR failed for {}.".format(session_name))
        return
    logger.info("sending CSR succeeded for {}.".format(session_name))
    return

@route("/csr", method="POST")
def app_csr():

    if request.headers["content-type"] != "application/json":
        logger.error("content-type must be JSON")
        return None

    body = request.body.read()
    logger.debug(body)
    # XXX the type of body is str in ubuntu.
    j = json.loads(body)
    csr_pem_b = j["csr"]
    session_name = j["session_name"]

    client_addr = (request.environ.get("HTTP_X_FORWARDED_FOR") or
                   request.environ.get("REMOTE_ADDR"))
    access_url = make_access_url(session_name, client_addr, opt)
    lead_time = get_lead_time()

    t = threading.Thread(target=worker, args=(session_name, client_addr,
                                              csr_pem_b, access_url, opt))
    t.start()

    response.content_type = "application/json"

    return json.dumps({
            "access_url": access_url,
            "lead_time": lead_time
            })

class SSLWSGIRefServer(ServerAdapter):

    def run(self, handler):
        server_cert = self.options.get("server_cert")
        self.options.pop("server_cert")
        srv = make_server(self.host, self.port, handler, **self.options)
        srv.socket = wrap_socket(srv.socket,
                                 certfile=server_cert,
                                 server_side=True)
        srv.serve_forever()

#
# main
#
opt, print_help = parse_args()
logger = set_logger(logging, opt.enable_debug)
if not opt.enable_debug:
    requests.packages.urllib3.disable_warnings()

# XXX get the initial parameter (e.g. lead_time) from CA.
# this should be another thread ?

logger.info("listen on https://{}:{}/".format(opt.bind_addr, opt.bind_port))
run(host=opt.bind_addr, port=opt.bind_port, server=SSLWSGIRefServer,
    quiet=not opt.enable_debug, debug=opt.enable_debug,
    server_cert=opt.my_cert)
