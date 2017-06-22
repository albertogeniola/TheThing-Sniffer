#!/usr/bin/python2.7
from analyzer_server import server
import getopt
import os
import sys
import logging

log = logging.getLogger("web_service")
hdlr = logging.StreamHandler(stream=sys.stdout)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
log.addHandler(hdlr)
hdlr.setLevel(logging.DEBUG)
log.setLevel(logging.DEBUG)


def usage():
    print('%s -b <bind_address> -p <bind_port>' % __file__)


def main(argv):
    if os.geteuid() != 0:
        raise Exception("This program must run as ROOT.")

    host = "0.0.0.0"
    port = 9090

    try:
        opts, args = getopt.getopt(argv, "hb:p:", ["bind=", "port="])
    except getopt.GetoptError:
        usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            usage()
            sys.exit(0)
        elif opt in ("-b", "--bind"):
            host = arg
        elif opt in ("-p", "--port"):
            port = int(arg)

    # Start the analyzer_server daemon
    server.start(host, port)


if __name__ == "__main__":
    main(sys.argv[1:])

