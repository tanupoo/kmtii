#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import sys
import argparse
import json
from hashlib import sha256
from datetime import datetime
import requests
import threading
from bottle import route, run, request, response, ServerAdapter
from ssl import wrap_socket
from wsgiref.simple_server import make_server
from kmtii_util import *

ap = argparse.ArgumentParser(
        description="""a proxy server implementation
        for the ip address certification.""",
        epilog="still in progress.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
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
                help="specify the number of transmitting count.")
ap.add_argument("-v", action="store_true", dest="verbose",
                help="enable verbose mode.")
ap.add_argument("-d", action="store_true", dest="enable_debug",
                help="enable debug mode.")

opt = ap.parse_args()

lead_time = 10

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
            "session_name": session_name,
            "access_url": access_url,
            })
    debug(http_body, opt.enable_debug)

    http_header = {}
    http_header["Content-Type"] = "application/json"
    http_header["Accept"] = "application/json"

    try:
        res = requests.request("POST", opt.ca_url, headers=http_header,
                            data=http_body, verify=opt.trust_server)
    except Exception as e:
        error("requests POST failed. {}".format(e))

    debug_http_post(res, opt.enable_debug)

    if res.ok:
        if opt.verbose:
            print("{} {}".format(res.status_code, res.reason))
        return True
    else:
        error("HTTP response {} {}\n{}".format(
                res.status_code, res.reason, res.text))
        return False

def worker(session_name, client_addr, csr_pem_b, access_url, opt):
    retry_count = opt.tx_count
    while True:
        ret = post_csr(csr_pem_b, client_addr, access_url, session_name, opt)
        if ret == True:
            log_ok("sending CSR succeeded for {}.".format(session_name))
            break
        retry_count -= 1
        if retry_count > 0:
            continue
        log_error("sending CSR failed for {}.".format(session_name))
        break

@route("/csr", method="POST")
def app_csr():

    if request.headers["content-type"] == "application/json":
        body = request.body.read()
        debug(body, opt.enable_debug)
        j = json.loads(body)
        csr_pem_b = j["csr"]
        session_name = j["session_name"]
    else:
        error("content-type must be JSON")

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

# XXX get the initial parameter (e.g. lead_time) from CA.
# this should be another thread ?

print("listen on https://{}:{}/".format(opt.bind_addr, opt.bind_port))
run(host=opt.bind_addr, port=opt.bind_port, server=SSLWSGIRefServer,
    quiet=False, debug=False,
    server_cert=opt.my_cert)
