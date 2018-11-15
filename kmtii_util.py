def debug(x, enable_debug):
    if enable_debug:
        print("DEBUG:", x)

def debug_http_post(res, enable_debug):
    debug("POST", enable_debug)
    debug("---- REQUEST HEADER ----", enable_debug)
    for k,v in res.request.headers.items():
        debug("{}: {}".format(k,v), enable_debug)
    debug("---- REQUEST BODY ----", enable_debug)
    debug("{} {} {}".format(res.request.method, res.request.path_url,
                                res.request.url), enable_debug)
    debug("---- RESPONSE HEADER ----", enable_debug)
    for k,v in res.headers.items():
        debug("{}: {}".format(k,v), enable_debug)
    debug("---- RESPONSE ----", enable_debug)

def log_ok(x):
    print("INFO:", x)

def error(x):
    print("ERROR:", x)
    exit(-1)

