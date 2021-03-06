#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function

import argparse
import json
from hashlib import sha256
from OpenSSL import crypto
import base64
import requests
from time import sleep
import threading
from bottle import route, run, request, response, ServerAdapter
from ssl import wrap_socket
from wsgiref.simple_server import make_server
import logging
from kmtii_util import set_logger, debug_http_post

lead_time = 10


def parse_args():
    ap = argparse.ArgumentParser(
        description="""a CA server implementation
            for the ip address certification.""",
        epilog="still in progress.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    ap.add_argument(
        "--ra-url",
        action="store",
        dest="ra_url",
        required=True,
        help="specify the URL of RA.")
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
        default=41888,
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
        "--tx-count",
        action="store",
        dest="tx_count",
        type=int,
        default=3,
        help="specify the number of transmitting count.")
    ap.add_argument(
        "--tx-interval",
        action="store",
        dest="tx_interval",
        type=int,
        default=5,
        help="specify the retransmit interval in seconds.")
    ap.add_argument(
        "--domain-name",
        action="store",
        dest="domain_name",
        help="specify the domain name.")
    ap.add_argument(
        "--cert-not-before",
        action="store",
        dest="not_before",
        type=int,
        default=30,
        help="specify the number of not_before in minutes.")
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


def post_cert(client_cert_pem, client_addr, session_name, access_url, opt):
    '''
    post CERT to RA.
    '''
    http_body = json.dumps({
        "cert":
        base64.b64encode(client_cert_pem).decode("utf-8"),
        "client_addr":
        client_addr,
        "session_name":
        session_name,
        "access_url":
        access_url,
    })
    logger.debug(http_body)

    http_header = {}
    http_header["Content-Type"] = "application/json"
    http_header["Accept"] = "application/json"

    tx_count = opt.tx_count
    while tx_count > 0:
        tx_count -= 1
        try:
            res = requests.request(
                "POST",
                opt.ra_url,
                headers=http_header,
                data=http_body,
                verify=opt.trust_server)
            break
        except Exception as e:
            logger.error("accessing Repository failed. {}".format(e))
            if tx_count == 0:
                return None, None
        sleep(opt.tx_interval)

    debug_http_post(res, logger)

    if not res.ok:
        logger.error("HTTP response {} {}\n{}".format(res.status_code,
                                                      res.reason, res.text))
        return False

    logger.debug("{} {}".format(res.status_code, res.reason))
    return True


def worker(csr_pem, client_addr, wan_addr, session_name, access_url, opt):
    # XXX need to check the parameter in CSR.
    # csr.get_subject()
    csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_pem)

    with open(opt.my_cert) as fd:
        signer_cert_pem = fd.read()
    signer_cert = crypto.load_certificate(crypto.FILETYPE_PEM, signer_cert_pem)

    with open(opt.my_cert) as fd:
        signer_key_pem = fd.read()
    signer_key = crypto.load_privatekey(crypto.FILETYPE_PEM, signer_key_pem)

    # serial number is a number which is less than 20 bytes.
    serial_num = int(sha256(csr.get_subject().der()).digest()[:20].hex(), 16)
    notBefore = -60 * opt.not_before
    notAfterVal = 60 * 60 * 24 * 14  # 2 weeks

    cert = crypto.X509()
    cert.set_version(2)
    cert.set_serial_number(serial_num)
    cert.gmtime_adj_notBefore(notBefore)
    cert.gmtime_adj_notAfter(notAfterVal)
    cert.set_issuer(signer_cert.get_subject())
    cert.set_subject(csr.get_subject())

    # add extensions
    san_list = [
        "IP: {}".format(wan_addr).encode(), "DNS: {}.{}".format(
            access_url[1 + access_url.rindex("/"):], opt.domain_name).encode()
    ]
    x509_ext = []
    for i in csr.get_extensions():
        # XXX need to check the content of the SAN.
        if i.get_short_name() == b'subjectAltName':
            x509_ext.append(i)
    x509_ext.append(
        # XXX need to canonicalize.
        crypto.X509Extension(
            type_name=b"subjectAltName",
            critical=False,
            value=b", ".join(san_list)))
    cert.add_extensions(x509_ext)

    cert.set_pubkey(csr.get_pubkey())
    cert.sign(signer_key, "sha256")

    csr_file = session_name + ".csr"
    client_cert_file = session_name + ".crt"

    with open(csr_file, "wb+") as fd:
        fd.write(csr_pem)

    client_cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    with open(client_cert_file, "wb+") as fd:
        fd.write(client_cert_pem)

    ret = post_cert(client_cert_pem, client_addr, session_name, access_url,
                    opt)
    if ret is not True:
        logger.error("sending CERT failed for {}.".format(session_name))
        return
    logger.info("sending CERT succeeded for {}.".format(session_name))
    return


@route("/csr", method="POST")
def app_csr():

    if request.headers["content-type"] == "application/json":
        body = request.body.read()
        logger.debug(body)
        j = json.loads(body)
        csr_pem = base64.b64decode(j["csr"])
        client_addr = j["client_addr"]
        wan_addr = j["wan_addr"]
        session_name = j["session_name"]
        access_url = j["access_url"]
    else:
        response.status = 415
        logger.info("content-type must be JSON")

    t = threading.Thread(
        target=worker,
        args=(
            csr_pem,
            client_addr,
            wan_addr,
            session_name,
            access_url,
            opt,
        ))
    t.start()

    response.content_type = "application/json"

    return json.dumps({"access_url": access_url, "lead_time": lead_time})


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
