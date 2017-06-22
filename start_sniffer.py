#!/usr/bin/python2.7
from router import conf, daemon, discovery_service
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

if __name__ == "__main__":
    if os.geteuid() != 0:
        raise Exception("This program must run as ROOT.")

    # This will initialize the manager object.
    mgr = daemon.mgr

    # Start the Broadcast receiver
    srv = discovery_service.UdpServer(mgr, conf.BDCAST_RECEIVER_ADDR, conf.BDCAST_RECEIVER_PORT)
    srv.start()

    # Start the sniffer
    os.chdir(os.path.dirname(daemon.__file__))
    daemon.app.run(port=conf.WEB_SERVICE_PORT)
