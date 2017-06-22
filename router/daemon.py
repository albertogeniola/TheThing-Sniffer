#!/usr/bin/env python
__author__ = 'Alberto Geniola'
import web
import sys
import os
import json
from subprocess import Popen, call
import re
import threading
import datetime
import logging
from .proxydump import MitmSnifferInstance
import zipfile
import shutil
import socket
from conf import *

# Configure logging asap.
log = logging.getLogger("web_service")
hdlr = logging.StreamHandler(stream=sys.stdout)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
log.addHandler(hdlr)
hdlr.setLevel(LOG_LEVEL)
log.setLevel(LOG_LEVEL)


def add_iptable_https_traffic_rule(mac, port):
    # First delete all the previous rules
    del_iptable_https_traffic_rule(mac, port)

    # Then add
    cmd = COMMAND % ('-A', str(CAPTURE_IF), str(mac), port)
    cmd = cmd.split()
    res = call(cmd)

    if res != 0:
        raise Exception("Cannot create forwarding rule for proxy")


def del_iptable_https_traffic_rule(mac, port):
    remove_cmd = COMMAND % ('-D', str(CAPTURE_IF), str(mac), port)
    remove_cmd = remove_cmd.split()
    while call(remove_cmd) == 0:
        pass


def VALID_MAC(mac):
    return re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", mac.lower())


class Sniffer(object):
    def __init__(self, mac, hc_ip, hc_port, mimt_port):
        self._lock = threading.RLock()
        self._p = None  # Process object for tcpdump instance
        self._mitm_instance = None  # Process object for MITMDump instance
        self._mac = mac
        self._returncode = None
        self._status = 'prepared'
        self._dest = None  # Path of tcpdump sniffed traffic
        self._dest_https = None  # Path of mitmdump sniffed traffic
        self._mitm_port = mimt_port  # Port used by the MITMDump process
        self._start_time="Never"
        self._stop_time="Never"
        self._hc_ip = hc_ip
        self._hc_port = hc_port

    @property
    def started_at(self):
        return self._start_time

    @property
    def stopped_at(self):
        return self._stop_time

    @property
    def status(self):
        if not self._p is None:
            self._p.poll()
            if not self._p.returncode is None:
                with self._lock:
                    self._status = 'finished'
                    self._returncode = self._p.returncode
        return self._status

    @property
    def mac(self):
        return self._mac

    @property
    def pid(self):
        if self._p is not None:
            return self._p.pid
        else:
            return None

    @property
    def pid_mitm(self):
        if self._mitm_instance is not None:
            return self._mitm_instance._proc.pid
        else:
            return None

    @property
    def dim(self):
        if self._dest is None:
            return 0

        if not os.path.isfile(self._dest):
            return 0

        return os.path.getsize(self._dest)

    @property
    def dim_https(self):
        if self._dest_https is None:
            return 0

        if not os.path.isfile(self._dest_https):
            return 0

        return os.path.getsize(self._dest_https)

    @property
    def cap_file(self):
        return self._dest

    @property
    def cap_file_https(self):
        return self._dest_https

    @property
    def exit_code(self):
        if not self._p is None:
            self._p.poll()
            return self._p.returncode
        else:
            return None

    @property
    def exit_code_mitm(self):
        if not self._mitm_instance is None:
            return self._mitm_instance._proc.exitcode
        else:
            return None

    def to_json_dict(self):
        res = {}

        # General info
        res['mac'] = self.mac
        res['status'] = self.status
        res['start_time'] = self.started_at
        res['stop_time'] = self.stopped_at

        # HTTPs traffic
        res['pid_mitm'] = self.pid_mitm
        res['size_https'] = self.dim_https
        res['exit_code_mitm'] = self.exit_code_mitm

        # Rest of Traffic
        res['pid'] = self.pid
        res['size'] = self.dim
        res['exit_code'] = self.exit_code

        return res

    def start(self):
        # Now we release the main lock and we get the lock on the single sniffer
        with self._lock:
            if self.status == "prepared" or self.status == "finished":
                self._status = "spawning"
                self._dest = os.path.join(PCAP_FOLDER_PATH, self.mac.replace(':', '_')+".pcap")
                self._dest_https = os.path.join(PCAP_FOLDER_PATH, self.mac.replace(':', '_')+"_https.pcap")

                # Redirect incoming HTTPs traffic through that proxy. Every connection established via HTTPS from
                # the given mac address will be redirected through the proxy
                # But only if it does not exist already.
                add_iptable_https_traffic_rule(self.mac, self._mitm_port)

                # Spawn a new MITMProxy for this sniffer
                self._mitm_instance = MitmSnifferInstance(self._mitm_port,
                                                          outfile=self._dest_https,
                                                          mode='transparent',
                                                          cadir=CA_DIR)
                self._mitm_instance.start()

                # Spawn classic TCPDUMP instance capturing all traffic to and from the guest machine, identified
                # by its mac address. Also, we immediately exclude from the capture all traffic to and from
                # the host controller, which is somewhat heavy and useless.
                filter_arg = '(ip and ether host %s) && ' \
                             '!(dst host %s) && ' \
                             '!(src host %s)' % (str(self.mac),
                                                                     str(self._hc_ip),
                                                                     str(self._hc_ip))
                self._p = Popen([TCPDUMP_EX, '-w', str(self._dest), '-C', str(MAX_PCAP_SIZE), '-W', '1', '-i', CAPTURE_IF,
                                 filter_arg])

                self._status = "running"
                self._start_time = str(datetime.datetime.utcnow())
            else:
                raise Exception("Sniffer is not in either 'prepared' nor 'finished' status. ")

    def stop(self):
        # Now we release the main lock and we get the lock on the single sniffer
        with self._lock:
            if self.status == "running":
                try:
                    self._status = "stopping"
                except:
                    pass

                try:
                    self._p.terminate()
                except:
                    pass

                try:
                    # This will block until the process fully exists
                    self._mitm_instance.stop()
                except:
                    pass

                # Wait for the processes to exit
                try:
                    self._p.wait()
                except:
                    pass


                # Destroy the associated iptables rule
                try:
                    del_iptable_https_traffic_rule(self.mac, self._mitm_port)
                except:
                    pass

                self._status = "finished"
                self._stop_time = str(datetime.datetime.utcnow())
            else:
                raise Exception("Sniffer is not in running state and cannot be terminated. ")


_BASE_MITM_PORT = 61666
_MAX_MITM_INSTANCES = 100


class Manager(object):
    _main_lock = threading.RLock()
    _sniffers = {}
    _mitm_ports = {}
    _hc_addr = None
    _hc_port = None

    def __init__(self):
        for i in range(0, _MAX_MITM_INSTANCES):
            self._mitm_ports[_BASE_MITM_PORT + i] = False

        self.generate_certs()

    def set_hc_address(self, address, port):
        """
        Store the address and port of the host to be contacted as HC for this sniffer.
        :param address: 
        :param port: 
        :return: 
        """
        with self._main_lock:
            self._hc_addr = address
            self._hc_port = port

    def get_hc_address(self):
        """
        Returns current address an port of HC controlling this sniffer.
        :return: 
        """
        with self._main_lock:
            return self._hc_addr, self._hc_port

    def list_sniffers(self):
        res = {}
        for s in self._sniffers:
            res[s] = self._sniffers[s].to_json_dict()
        return json.dumps(res)

    def get_sniffer(self, mac):
        if mac is None or isinstance(mac, str) or not VALID_MAC(mac):
            raise Exception("Invalid mac")

        with self._main_lock:
            if self._sniffers.has_key(mac):
                return self._sniffers[mac]
            else:
                raise Exception("There is no sniffer for this mac address")

    def has_sniffer(self, mac):
        with self._main_lock:
            return self._sniffers.has_key(mac)

    def prepare_sniffer(self, mac, hc_ip, hc_port):
        """
        Prepares data structure for a new sniffer process to capture traffic to and from the given
        MAC Address. If there already is a sniffer for that mac address, an error
        is raised.
        :param mac: string
        :return: void
        """
        if mac is None or isinstance(mac, str) or not VALID_MAC(mac):
            raise Exception("Invalid mac")

        # Add the sniffer object into the list if not already present.
        with self._main_lock:
            if not self._sniffers.has_key(mac):
                # Pick the first free port
                mitm_port = -1
                for key, value in self._mitm_ports.iteritems():
                    if value == False:
                        mitm_port = key
                        break

                if mitm_port == -1:
                    raise Exception("Maximum number of mitm instances reached!")

                s = Sniffer(mac=mac, hc_ip=hc_ip, hc_port=hc_port, mimt_port=mitm_port)

                # Set the port as occupied
                self._mitm_ports[mitm_port] = True
                self._sniffers[mac] = s

    def delete_sniffer(self, mac):
        """
        Deletes a sniffer that has been prepared. It simply removes the metadata structure on this service
        associated to the sniffer with given mac. The sniffer must be in the PREPARED or FINISHED status.
        :param mac: string
        :return: void
        """
        if mac is None or isinstance(mac, str) or not VALID_MAC(mac):
            raise Exception("Invalid mac")

        # Add the sniffer object into the list if not already present.
        with self._main_lock:
            s = self.get_sniffer(mac)
            if s.status == 'prepared' or s.status == 'finished':
                self._sniffers.pop(mac)
                # TODO: should we remove the pcap file?
            else:
                raise Exception("The sniffer is into an invalid status to be deleted.")

    def generate_certs(self):
        """
        Generate new certificates for the MITMProxy and store them in CA_DIR
        :return: 
        """
        from OpenSSL import crypto, SSL
        import random, string
        from shutil import copyfile

        log.info("Generating ceritificates...")
        if not os.path.isdir(CA_DIR):
            log.warn("Directory %s did not exist. I will create it." % CA_DIR)
            os.makedirs(CA_DIR)

        ca_pem = os.path.join(CA_DIR,'mitmproxy-ca.pem')
        ca_cert_cer = os.path.join(CA_DIR, 'mitmproxy-ca-cert.cer')
        ca_cert_p12 = os.path.join(CA_DIR, 'mitmproxy-ca-cert.p12')
        ca_cert_pem = os.path.join(CA_DIR, 'mitmproxy-ca-cert.pem')

        N = random.randint(3, 10)
        snumber = random.randint(1000, 9999999999)

        # create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)

        # Generate a random string certificate.
        # This is a simple attempt to avoid easy detection of mitm proxy on the sandbox
        entity = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(N))

        # create a self-signed cert
        cert = crypto.X509()
        cert.get_subject().OU = entity
        cert.get_subject().CN = entity
        cert.set_serial_number(snumber)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha1')

        # We now export the certificate in various formats
        with open(ca_pem, "wt") as t:
            t.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))
            t.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

        with open(ca_cert_pem, "wt") as t:
            t.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

        copyfile(ca_cert_pem, ca_cert_cer)

        pfx = crypto.PKCS12Type()
        pfx.set_privatekey(k)
        pfx.set_certificate(cert)
        pfxdata = pfx.export()
        with open(ca_cert_p12, "wb") as t:
            t.write(pfxdata)


class WebSniffers(object):

    def GET(self):
        """
        Display a list of all the current sniffers working
        :return:
        """
        web.header('Content-Type', 'application/json')
        web.ctx.status = '200 OK'
        return web.mgr.list_sniffers()

    def POST(self):
        """
        Spawns a sniffer. This method requires a mac_address to filter the traffic.
        :return:
        """

        # Parse the input
        data = None
        try:
            raw = web.data()
            data = json.loads(raw)
            if data['mac'] is None:
                raise Exception("Missing mac parameter")
            if not VALID_MAC(data['mac']):
                raise Exception("Invalid mac parameter")
            """
            # Not necessary any longer, now HC_IP and HC_PORT are registered once for all from the HC when the sniffer is started.
            if data['hc_ip'] is None:
                raise Exception("Missing hc_ip parameter")
            if data['hc_port'] is None:
                raise Exception("Missing hc_port parameter")
            """
        except:
            raise web.badrequest("Invalid or missing mac parameter.")

        if web.mgr.has_sniffer(data['mac']):
            web.ctx.status = '409 Conflict'
            return ""

        # Execute the operation
        try:
            hc_addr, hc_port = web.mgr.get_hc_address()

            # Check if the host controller has already registered to this sniffer. In case it didn't, return the error
            if hc_addr is None or hc_port is None:
                return web.badrequest("HostController address or port has not been set yet. Please register the HostController first to this sniffer.")

            web.mgr.prepare_sniffer(data['mac'], hc_addr, hc_port)
            web.header('Content-Type', 'application/json')
            web.ctx.status = '201 Created'
            return ""
        except:
            log.exception("Error when preparing the sniffer")
            raise web.internalerror("Error when preparing sniffer.")


class WebSniffer(object):

    def GET(self, mac):
        s = None
        try:
            if not VALID_MAC(mac):
                raise Exception("Invalid mac")
            s = web.mgr.get_sniffer(mac)
            web.header('Content-Type', 'application/json')
            web.ctx.status = '200 OK'
            return json.dumps(s.to_json_dict())
        except Exception as e:
            raise web.notfound(e)

    def DELETE(self, mac):
        s = None
        try:
            if not VALID_MAC(mac):
                raise Exception("Invalid mac")
            s = web.mgr.get_sniffer(mac)
        except Exception as e:
            raise web.notfound(e)

        try:
            web.mgr.delete_sniffer(mac)
        except Exception as e:
            raise web.internalerror(e)


class HostControllerAddress(object):
    def POST(self):
        """
        Publishes the HostController address to be used by the sniffer.
        The payload must just contain json object like:
        {"hc_address":"XXX.XXX.XXX.XXX"}
        :return: 
        """

        # Parse input
        data = None
        address = None
        port = None

        try:
            raw = web.data()
            data = json.loads(raw)
        except:
            raise web.badrequest("Invalid payload. Please provide a valid JSON encoded payload")

        if 'address' not in data:
            raise web.badrequest("Missing address parameter")
        else:
            address = data['address']

        if 'port' not in data:
            raise web.badrequest("Missing port parameter")

        try:
            p = data.get('port')
            port = int(p)
            if port < 1 or port > 65535:
                raise ValueError()
        except:
            raise web.badrequest('Invalid port specified.')

        """
        # Try to contact the HostController directly from here. Note thta HostController must be already running
        # for this to work. We just want to establish a successful connection with the HostController.
        conn = None
        try:
            conn = socket.create_connection(address=(address, port))

            # Upon successful connection we save data into the manager.
            web.mgr.set_hc_address(address, port)
            log.info("New HC Address published: %s:%d" % (address, port))
            return web.OK()
        except:
            raise web.badrequest("Connection attempt against HostController failed. Please check that the HostController is running and network configuration is OK.")
        finally:
            if conn is not None:
                conn.close()
        """
        web.mgr.set_hc_address(address, port)
        return web.OK()

class AgentSoftwareHandler(object):
    def GET(self, platform, release, arch):
        """
        Download a specific Sandbox Agent, given the OS type
        :param os:
        :param agent_ver:
        :return:
        """

        # Sanitize os and version.
        if not re.match("^[a-zA-Z0-9\_]+$", platform):
            raise web.badrequest("Platform value is unsafe and will not be accepted.")

        if not re.match("^[a-zA-Z0-9\_]+$", release):
            raise web.badrequest("Release value is unsafe and will not be accepted.")

        if not re.match("^[a-zA-Z0-9\_]+$", arch):
            raise web.badrequest("Arch value is unsafe and will not be accepted.")

        # Calculate the path
        dest_path = os.path.join(AGENT_CLIENT_DIR, platform, release, arch)
        if not os.path.isdir(dest_path):
            os.makedirs(dest_path)

        # Check if the file exists and serve it back
        filename = os.path.join(dest_path, "agent.zip")

        if not os.path.isfile(filename):
            raise web.notfound("Agent version not found on this sniffer.")

        stats = os.stat(filename)

        web.header('Content-Type', 'application/octet-stream')
        web.header('Content-Disposition', 'attachment; filename="agent.zip"')
        web.header('Content-Length', '%d' % stats.st_size)
        web.ctx.status = '200 OK'
        return open(filename, "rb").read()

    def POST(self, platform, release, arch):
        """
        Publish a new Sandbox Agent.
        :param os:
        :param agent_ver:
        :return:
        """
        x = web.input(agent_file={})
        if 'agent_file' not in x:
            # Raise the exception now.
            raise web.badrequest("Missing parameter agent_file.")

        if 'agent_file' in x:
            # Sanitize os and version.
            if not re.match("^[a-zA-Z0-9\_]+$", platform):
                raise web.badrequest("Platform value is unsafe and will not be accepted.")

            if not re.match("^[a-zA-Z0-9\_]+$", release):
                raise web.badrequest("Release value is unsafe and will not be accepted.")

            if not re.match("^[a-zA-Z0-9\_]+$", arch):
                raise web.badrequest("Arch value is unsafe and will not be accepted.")

            # Create the path
            dest_path = os.path.join(AGENT_CLIENT_DIR, platform, release, arch)
            if not os.path.isdir(dest_path):
                os.makedirs(dest_path)

            # Store the file there
            filename = os.path.join(dest_path, "agent.zip")

            fout = None
            try:
                with open(filename, 'w') as fout: # creates the file where the uploaded file should be stored
                    fout.write(x.agent_file.file.read()) # writes the uploaded file to the newly created file.

                if not zipfile.is_zipfile(filename):
                    raise web.badrequest("Corrupted or invalid zip file.")

                zfile = zipfile.ZipFile(file=filename)
                if zfile.testzip() is not None:
                    raise web.badrequest("Invalid or corrupted zip file")

                # Everything OK. Return success.
                return web.created()

            except:
                log.exception("Error during agent client upload")
                # If file was too big or invalid, delete it.
                try:
                    fout.close()
                except:
                    pass

                # Remove the entire directory of agent.
                if os.path.isfile(filename):
                    shutil.rmtree(dest_path)

                # Raise the exception now.
                raise web.badrequest("Error during upload of agent.")


class CertificateHandler(object):
    def GET(self):
        try:
            # Just return the certificate used for traffic sniffer
            web.header('Content-Type', 'application/octet-stream')
            web.header('Content-Disposition', 'attachment; filename="mitmproxy-ca-cert.p12"')
            web.ctx.status = '200 OK'
            return open(os.path.join(CA_DIR, "mitmproxy-ca-cert.p12"), "rb").read()
        except Exception as e:
            raise web.badrequest(e)


class WebSnifferActions(object):
    def GET(self, mac, action):
        try:
            if not VALID_MAC(mac):
                raise Exception("Invalid mac")
            if action.lower() == "start":
                s = web.mgr.get_sniffer(mac)
                s.start()
                web.header('Content-Type', 'application/json')
                web.ctx.status = '200 OK'
                return json.dumps(s.to_json_dict())
            elif action.lower() == "stop":
                s = web.mgr.get_sniffer(mac)
                s.stop()
                web.header('Content-Type', 'application/json')
                web.ctx.status = '200 OK'
                return json.dumps(s.to_json_dict())
            elif action.lower() == "collect":
                s = web.mgr.get_sniffer(mac)
                if s.status != 'finished':
                    raise Exception("Invalid status: sniffer must be in finished status for collecting its logs.")
                web.header('Content-Type', 'application/octet-stream')
                web.header('Content-Disposition', 'attachment; filename="'+s.cap_file+'"')
                web.ctx.status = '200 OK'
                return open(s.cap_file,"rb").read()
            elif action.lower() == "collect_https":
                s = web.mgr.get_sniffer(mac)
                if s.status != 'finished':
                    raise Exception("Invalid status: sniffer must be in finished status for collecting its logs.")
                web.header('Content-Type', 'application/octet-stream')
                web.header('Content-Disposition', 'attachment; filename="'+s.cap_file_https+'"')
                web.ctx.status = '200 OK'
                return open(s.cap_file_https, "rb").read()
            elif action.lower() == "delete_log":
                s = web.mgr.get_sniffer(mac)
                if s.status != 'finished':
                    raise Exception("Invalid status: sniffer must be in finished status in order to remote its logs.")
                os.unlink(s.cap_file)
                os.unlink(s.cap_file_https)
                web.ctx.status = '204 No content'
                return
            else:
                raise Exception("Invalid action")

        except Exception as e:
            log.exception("Exception happened.")
            raise web.badrequest(e)


class index:
    def GET(self):
        # redirect to the static file ...
        raise web.seeother('/static/index.html')

urls = (
    '^/sniffers$', 'WebSniffers',
    '^/sniffers/(.+)$', 'WebSniffer',
    '^/manager/(.+)/(.+)$', 'WebSnifferActions',
    '^/certificate$', 'CertificateHandler',
    '^/hc_address$', 'HostControllerAddress',
    '^/agents/(.+)/(.+)/(.+)$', 'AgentSoftwareHandler',
    '/', 'index'
)


class WebService(web.application):
    def run(self, port=8080, *middleware):
        func = self.wsgifunc(*middleware)
        return web.httpserver.runsimple(func, ('0.0.0.0', port))


# We need to chdir into this directory
app = WebService(urls, globals())
mgr = Manager()
web.mgr = mgr
