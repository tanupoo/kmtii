#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import sys
import argparse
import json
from datetime import datetime
from OpenSSL import crypto
import base64
import requests
import threading
from bottle import route, run, request, response, ServerAdapter
from ssl import wrap_socket
from wsgiref.simple_server import make_server
from kmtii_util import *

ap = argparse.ArgumentParser(
        description="""an RA server implementation
        for the ip address certification.""",
        epilog="still in progress.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
ap.add_argument("--bind-addr", action="store", dest="bind_addr",
                default="0.0.0.0",
                help="specify the address to be bound.")
ap.add_argument("--bind-port", action="store", dest="bind_port",
                type=int, default=41888,
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

@route("/state")
def app_state():
    # XXX in seconds. it should be taken from CA.
    global lead_time
    response.content_type = "application/json"
    return json.dumps({
            "ra_url": opt.ra_url,
            "lead_time": lead_time
            })

cert_tab = {}

# dynamic route
def responder():
    # check the request
    if request.headers["content-type"] == "application/json":
        body = request.body.read()
        debug(body, opt.enable_debug)
        j = json.loads(body)
        session_name = j["session_name"]
    else:
        error("content-type must be JSON")

    route_key = request.path[request.path.rindex("/"):]
    client_cert_info = cert_tab.get(route_key)
    if client_cert_info is None:
        error("route_key {} is not valid.".format(route_key))

    if client_cert_info["session_name"] != session_name:
        error("session_name mismatched. db({}) req({})".format(
                client_cert_info["session_name"], session_name))

    debug(client_cert_info, opt.enable_debug)
    response.content_type = "application/json"
    return json.dumps(client_cert_info)

@route("/cert", method="POST")
def app_cert():

    if request.headers["content-type"] == "application/json":
        body = request.body.read()
        debug(body, opt.enable_debug)
        j = json.loads(body)
        client_cert_pem = base64.b64decode(j["cert"])
        client_addr = j["client_addr"]
        session_name = j["session_name"]
        access_url = j["access_url"]
    else:
        error("content-type must be JSON")

    client_cert_file = session_name + ".crt"
    with open(client_cert_file, "wb+") as fd:
        fd.write(client_cert_pem)

    route_key = access_url[access_url.rindex("/"):]
    cert_tab[route_key] = {
            "cert": base64.b64encode(client_cert_pem).decode("utf-8"),
            "session_name": session_name
            }
    route(route_key, method="POST", callback=responder)

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
