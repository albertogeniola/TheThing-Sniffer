from socket import *
import select
import conf
import json
from threading import Thread
import re
from conf import *
import logging
import sys
import os

log = logging.getLogger("discovery_service")
hdlr = logging.StreamHandler(stream=sys.stdout)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
log.addHandler(hdlr)
hdlr.setLevel(conf.LOG_LEVEL)
log.setLevel(conf.LOG_LEVEL)


class UdpServer(object):
    s = None
    t = None
    ended = False
    mgr = None
    addr = None
    port = None

    def __init__(self, manager_ref, bind_on='0.0.0.0', port=9000):
        self.mgr = manager_ref
        self.addr = bind_on
        self.port = port

        self.s = socket(AF_INET, SOCK_DGRAM)

        self.t = Thread(target=self._run)

    def start(self):
        self.t.start()

    def stop(self):
        self.ended = True

    def _run(self):
        # Bind and listen on all interfaces.
        self.s.bind((self.addr, self.port))
        log.info("Discovery service bound on %s:%d" % (self.addr, self.port))

        while not self.ended:
            try:
                # Wait for packets...
                rlist = [self.s]
                rready, wready, xready = select.select(rlist, [], rlist, 0.5)

                # If there is a packet to process, go ahead.
                if self.s in rready:
                    self._handle_packet()

                # Otherwise we got a timeout. Keep rolling baby!
            except error:
                log.exception("Error when processing a packet.")

    def _handle_packet(self):
        packet, addr = self.s.recvfrom(4096)
        log.info("Received packet from %s:%d." % (addr[0], addr[1]))

        # Parse the packet.
        p = json.loads(packet)

        # The packet MUST contain:
        # msg -> HELO
        # platform -> Windows
        # release -> 7
        # version -> 5.1.XXXX
        msg = p.get('msg')
        platform = p.get('platform')
        release = p.get('release')
        arch = p.get('arch')

        if msg is None or msg != 'HELO':
            raise Exception("Missing or invalid message type.")

        if platform is None:
            raise Exception("Missing platform information.")

        if release is None:
            raise Exception("Missing release information.")

        if arch is None:
            raise Exception("Missing arch information.")

        # Lookup a valid GuestAgent for the that client
        hc_addr, hc_port = self.mgr.get_hc_address()

        # Compose the url for the certificate download as well.
        agent_url = self._lookup_agent(addr[0], platform, release, arch)
        cert_url = "http://%s:%d/certificate" % (self._find_local_ip_for_route(addr[0]), conf.WEB_SERVICE_PORT)

        resp = {"msg": "HELO_YOU",
                "hc_addr": hc_addr,
                "hc_port": hc_port,
                "agent_url": agent_url,
                "cert_url": cert_url}

        data = json.dumps(resp)
        log.info("Sending back %s to %s:%d." % (data, addr[0],addr[1]))
        self.s.sendto(data,addr)

    def _lookup_agent(self, remote_addr, platform, release, arch):

        # Sanitize os and version.
        if not re.match("^[a-zA-Z0-9\_]+$", platform):
            raise Exception("Platform value is unsafe and will not be accepted.")

        if not re.match("^[a-zA-Z0-9\_]+$", release):
            raise Exception("Release value is unsafe and will not be accepted.")

        if not re.match("^[a-zA-Z0-9\_]+$", arch):
            raise Exception("Arch value is unsafe and will not be accepted.")

        # Calculate the path
        dest_path = os.path.join(conf.AGENT_CLIENT_DIR, platform, release, arch)
        if not os.path.isdir(dest_path):
            os.makedirs(dest_path)

        # Check if the file exists and serve it back
        filename = os.path.join(dest_path, "agent.zip")

        if not os.path.isfile(filename):
            # We don't support such guest!
            return None
        else:
            return "http://%s:%d/agents/%s/%s/%s" % (self._find_local_ip_for_route(remote_addr), conf.WEB_SERVICE_PORT, platform, release, arch)

    def _find_local_ip_for_route(self, remote_ip):
        tmp = socket(AF_INET, SOCK_DGRAM)
        try:
            tmp.connect((remote_ip, 80))
        except:
            pass
        finally:
            addr = tmp.getsockname()[0]
            tmp.close()
            return addr
