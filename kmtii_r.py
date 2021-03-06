#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import argparse
import json
import base64
import requests
from bottle import route, run, request, response, ServerAdapter
from ssl import wrap_socket
from wsgiref.simple_server import make_server
import logging
from kmtii_util import set_logger

lead_time = 10


def parse_args():
    ap = argparse.ArgumentParser(
        description="""an RA server implementation
            for the ip address certification.""",
        epilog="still in progress.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument(
        "--bind-addr",
        action="store",
        dest="bind_addr",
        default="0.0.0.0",
        help="specify the address to be bound.")
    ap.add_argument(
        "--bind-port",
        action="store",
        dest="bind_port",
        type=int,
        default=41889,
        help="specify the port number to be bound.")
    ap.add_argument(
        "--my-cert",
        action="store",
        dest="my_cert",
        required=True,
        help="specify the certificate of mine.")
    ap.add_argument(
        "--untrust",
        action="store_false",
        dest="trust_server",
        help="disable to check the server certificate.")
    ap.add_argument(
        "-v", action="store_true", dest="verbose", help="enable verbose mode.")
    ap.add_argument(
        "-d",
        action="store_true",
        dest="enable_debug",
        help="enable debug mode.")
    opt = ap.parse_args()
    return opt, ap.print_help


@route("/state")
def app_state():
    # XXX in seconds. it should be taken from CA.
    global lead_time
    response.content_type = "application/json"
    return json.dumps({"ra_url": opt.ra_url, "lead_time": lead_time})


cert_tab = {}


# dynamic route
# XXX need to be removed in a few hours.
def responder():
    # check the request
    if request.headers["content-type"] == "application/json":
        body = request.body.read()
        logger.debug(body)
        j = json.loads(body)
        session_name = j["session_name"]
    else:
        msg = "content-type must be application/json"
        logger.error(msg)
        response.status = 400
        return msg

    route_key = request.path[request.path.rindex("/"):]
    client_cert_info = cert_tab.get(route_key)
    if client_cert_info is None:
        msg = "the access url {} is not valid.".format(route_key)
        logger.error(msg)
        response.status = 400
        return msg

    if client_cert_info["session_name"] != session_name:
        msg = "session_name mismatched. db({}) req({})".format(
            client_cert_info["session_name"], session_name)
        logger.error(msg)
        response.status = 400
        return "Bad Request"  # XXX don't send the internal session_name.

    logger.debug(client_cert_info)
    response.content_type = "application/json"
    return json.dumps(client_cert_info)


@route("/cert", method="POST")
def app_cert():

    if request.headers["content-type"] == "application/json":
        body = request.body.read()
        logger.debug(body)
        j = json.loads(body)
        client_cert_pem = base64.b64decode(j["cert"])
        # client_addr = j["client_addr"]
        session_name = j["session_name"]
        access_url = j["access_url"]
    else:
        msg = "content-type must be application/json"
        logger.error(msg)
        response.status = 400
        return msg

    client_cert_file = session_name + ".crt"
    with open(client_cert_file, "wb+") as fd:
        fd.write(client_cert_pem)

    route_key = access_url[access_url.rindex("/"):]
    cert_tab[route_key] = {
        "cert": base64.b64encode(client_cert_pem).decode("utf-8"),
        "session_name": session_name
    }
    route(route_key, method="POST", callback=responder)
    return


class SSLWSGIRefServer(ServerAdapter):
    def run(self, handler):
        server_cert = self.options.get("server_cert")
        self.options.pop("server_cert")
        srv = make_server(self.host, self.port, handler, **self.options)
        srv.socket = wrap_socket(
            srv.socket, certfile=server_cert, server_side=True)
        srv.serve_forever()


#
# main
#
opt, print_help = parse_args()
logger = set_logger(logging, opt.enable_debug)
if not opt.enable_debug:
    requests.packages.urllib3.disable_warnings()

logger.info("listen on https://{}:{}/".format(opt.bind_addr, opt.bind_port))
run(host=opt.bind_addr,
    port=opt.bind_port,
    server=SSLWSGIRefServer,
    quiet=not opt.enable_debug,
    debug=opt.enable_debug,
    server_cert=opt.my_cert)
