
def set_logger(logging, enable_debug):
    LOG_FMT = "%(asctime)s.%(msecs)d %(message)s"
    LOG_DATE_FMT = "%Y-%m-%dT%H:%M:%S"
    logging.basicConfig(format=LOG_FMT, datefmt=LOG_DATE_FMT)
    logger = logging.getLogger("kmtii_r")

    if enable_debug:
        logger.setLevel(logging.DEBUG)
        logger_urllib3 = logging.getLogger("requests.packages.urllib3")
        logger_urllib3.setLevel(logging.DEBUG)
        logger_urllib3.propagate = True
    else:
        logger.setLevel(logging.INFO)

    return logger

def debug_http_post(res, logger):
    logger.debug("POST")
    logger.debug("---- REQUEST HEADER ----")
    for k,v in res.request.headers.items():
        logger.debug("{}: {}".format(k,v))
    logger.debug("---- REQUEST BODY ----")
    logger.debug("{} {} {}".format(res.request.method, res.request.path_url,
                                res.request.url))
    logger.debug("---- RESPONSE HEADER ----")
    for k,v in res.headers.items():
        logger.debug("{}: {}".format(k,v))
    logger.debug("---- RESPONSE ----")

