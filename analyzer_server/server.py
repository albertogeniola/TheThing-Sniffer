import os
import subprocess
import tempfile
import logging
import json
import shutil
import magic
import patoolib
import ssdeep
from hashlib import md5, sha1
from threading import Timer
from mitmproxy import flow as Flow
import base64
import socket
import struct
import sys
import threading

# Maximum time for each command before exiting.
# At the moment is 10 minutes
MAX_COMMAND_TIME = 600
mime = magic.Magic(mime=True)
BUFFLEN=1024*1024
GENERAL_TIMEOUT = 30  # Timeout used for every network operation except connect/accept.

# Logging configuration
log = logging.getLogger("network_analyzer")
hdlr = logging.StreamHandler(stream=sys.stdout)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
log.addHandler(hdlr)
hdlr.setLevel(logging.DEBUG)
log.setLevel(logging.DEBUG)


def _which(program):
    import os
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file

    raise Exception("Cannot find executable path for %s" % program)


# Run some checks when this module gets imported: check tshark and tcpflow are installed
TSHARK_EX = _which("tshark")
BRO_EX = _which("bro")
BRO_SCRIPT = os.path.join(os.path.dirname(__file__), "main.bro")

if TSHARK_EX is None:
    raise Exception("tshark hasn't been found on this system. Please install it and add it to the PATH")


def kill_proc(processes):
    log.error("XXX Timer expired. Killing processes.")
    for p in processes:
        p.terminate()


def analyse_https(data, https_file):
    # NOTE: data here is not aggregated at domain layer. We just copy-paste all the requests into the dicitonary

    if not isinstance(data, dict):
        raise Exception("This method requires a dictionary as data")

    # Check if the capture file exists
    if not os.path.exists(https_file):
        raise Exception("PCAP File does not exist.")
    else:
        https_file = os.path.abspath(https_file)

    # Extract https_requests
    requests = []
    downloads = []
    with open(https_file, "rb") as logfile:
        freader = Flow.FlowReader(logfile)
        # For each flow, get the relative request
        for flow in freader.stream():
            r = dict()
            r['first_line_format']=str(flow.request.first_line_format)
            r['method']=flow.request.method
            r['scheme']=flow.request.scheme
            r['host']=flow.request.host
            r['hostname']=flow.request.pretty_host
            r['port']=flow.request.port
            r['path']=flow.request.path
            r['http_version']=flow.request.http_version
            #r['headers']=flow.request.data.headers
            # We also log the contents of the request. This might cause the log file to grow...
            r['content']=base64.encodestring(flow.request.content)
            r['timestamp_start']=flow.request.timestamp_start
            r['timestamp_end']=flow.request.timestamp_end
            r['fullpath']=flow.request.url

            requests.append(r)

            if (flow.response is not None) and (flow.response.content is not None) and len(flow.response.content) > 0:
                # In order to analyze the response content, we need to store it on disk
                with tempfile.NamedTemporaryFile(delete=True) as fp:
                    fp.write(flow.response.content)
                    fp.flush()

                    # Define a recursive function used whenever the file is an archive, so we can deep inspect all the
                    # contained files
                    def recursive_analysis(flow, fname, parent_archive_sha1, nest_level, downloads):
                        m_type = mime.from_file(fname)
                        size = os.path.getsize(fname)
                        with open(fname,'r') as f:
                            # Retrieve basic info about this file, such as MD5, SHA1, etc.
                            m = md5()
                            s = sha1()
                            f.seek(0,0)
                            for chunk in iter(lambda: f.read(4096), b""):
                                m.update(chunk)
                                s.update(chunk)

                            str_md5 = m.hexdigest()
                            str_sha1 = s.hexdigest()

                            str_fuzzy = ssdeep.hash_from_file(f.name)

                            # Store info on the referenced dict
                            d = dict()
                            d['host'] = flow.request.host
                            d['hostname'] = flow.request.pretty_host
                            d['port'] = flow.request.port
                            d['path'] = flow.request.path
                            d['scheme'] = flow.request.scheme
                            d['method'] = flow.request.method
                            #d['request_headers'] = flow.request.headers
                            d['status_code'] = flow.response.status_code
                            d['fullpath'] = r['fullpath']
                            #d['response_headers'] = flow.response.status_code
                            d['sha1'] = str_sha1.lower()
                            d['md5'] = str_md5.lower()
                            d['fuzzy'] = str_fuzzy.lower()
                            d['mime'] = m_type
                            d['size'] = size
                            d['parent_archive'] = parent_archive_sha1
                            d['nest_level'] = nest_level

                            downloads.append(d)

                            # Try to extract the file if it is an archive
                            tmpdir = tempfile.mkdtemp()
                            try:
                                # Brute force approach: we don't even check the mime file.
                                # We try to unpack evey archive.
                                # Extract all the files
                                patoolib.extract_archive(f.name, outdir=tmpdir)

                                # Analyze each file
                                files = [os.path.join(tmpdir,ff) for ff in os.listdir(tmpdir) if os.path.isfile(os.path.join(tmpdir, ff))]
                                for ff in files:
                                    recursive_analysis(flow, ff, str_sha1, nest_level+1, downloads)
                            except:
                                pass
                            finally:
                                # Remove the temporary file directory
                                shutil.rmtree(tmpdir)

                    recursive_analysis(flow, fp.name, None, 0, downloads)


    # Assign data to the dictionary
    data['https_requests'] = requests
    data['https_downloads'] = downloads


def analyse_pcap(data, pcap_file, network_conf):
    """
    This method executes the entire analysis of the given pcap. It executes each stepo of network analysis as follows:
    -> TSHARK: extract resoved hosts
    -> BRO: Gather L4 information on protocols and conversations
    -> BRO: Gather L7 information on FTP, DNS, HTTP, and any other enabled protocol inspector

    Note: HTTPS info is not handled here. We delegate its analysis via analyze_https method.

    :param data: Dictionary object where to store outcomes of the analysis
    :param pcap_file: Path to capture file to be analyzed
    :return:
    """

    if not isinstance(data, dict):
        raise Exception("This method requires a dictionary as data")

    # Check if the capture file exists
    if not os.path.exists(pcap_file):
        raise Exception("PCAP File does not exist.")
    else:
        pcap_file = os.path.abspath(pcap_file)

    # Calculate resolved hosts.
    _tshark_hosts(pcap_file, data)
    _bro_l4_l7_analysis(pcap_file, data, network_conf)


def _tshark_hosts(pcap_file, resp):
    """
    Retrieve all the resolved hosts using tshark utility.
    :param pcap_file:
    :param resp: the dictionary object where to put extracted info.
    :return: void
    """

    # Resolved hostnames.
    # We also set up a maximum time for analysis. We kill the process after MAX_COMMAND_TIME.
    p1 = subprocess.Popen([TSHARK_EX, '-r', pcap_file, '-q', '-z', 'hosts'], stdout=subprocess.PIPE)
    timer = Timer(MAX_COMMAND_TIME, kill_proc, p1)
    try:
        timer.start()

        # The following will block until the process finishes
        out1, err1 = p1.communicate()
    finally:
        timer.cancel()

    if p1.returncode != 0:
        raise Exception("Hostname resolution logging failed. Tshark returned %d" % p1.returncode)

    # Parse corresponding output
    resp['resolved_hosts'] = dict()
    for line in out1.split('\n'):
        # Skip headers and info data
        if line.startswith('#') or line == '':
            continue

        ip, host = line.strip().split()

        resp['resolved_hosts'][ip] = host


def _bro_l4_l7_analysis(pcap_file, resp, network_conf):
    """
    This method takes care of extracting L4 and L7 info from network capture file. It uses BRO as network
    analizer to achieve such goal.
    :param pcap_file:
    :param resp:
    :param host_controller_ip:
    :param host_controller_port:
    :return:
    """

    # Let's first start by running BRO and extracting basic logs.
    # We'll also need to filter out traffic generated to/from our analysis infrastructure.
    bro_filter = "!(dst host %s && tcp && dst port %d) && !(src host %s && tcp && src port %d)" %\
                 (network_conf['hc_ip'],network_conf['hc_port'],network_conf['hc_ip'],network_conf['hc_port'])

    # We'll also need a temporary directory where to store temporary logs
    tmpdir = tempfile.mkdtemp()
    try:
        p1 = subprocess.Popen([BRO_EX, '-r', pcap_file, '-C', '-f', bro_filter, BRO_SCRIPT], stdout=subprocess.PIPE, cwd=tmpdir)
        timer = Timer(MAX_COMMAND_TIME, kill_proc, p1)
        try:
            timer.start()

            # The following will block until the process finishes
            out1, err1 = p1.communicate()
        finally:
            timer.cancel()

        if p1.returncode != 0:
            raise Exception("BRO analysis failed. Return code was %d" % p1.returncode)

        # Here, we have logged data as calculated by BRO. Traffic to/from host controller is already filtered.
        # We just need to put all lines together into the conversation list; in the meanwhile we also collect network
        # protocols statistics
        resp['conversations'] = []
        resp['protocols'] = dict()
        resp['dns'] = []
        resp['http'] = []
        resp['ftp'] = []
        resp['files'] = []

        # First process conn file
        connfile = os.path.join(tmpdir,"conn.log")
        if os.path.exists(connfile):
            __parse_conn_file(resp, connfile, network_conf)

        # Then let's handle some L7 protocol.
        dnsfile = os.path.join(tmpdir,"dns.log")
        if os.path.exists(dnsfile):
            __parse_dns_file(resp, dnsfile, network_conf)

        httpfile = os.path.join(tmpdir, "http.log")
        if os.path.exists(httpfile):
            __parse_http_file(resp, httpfile, network_conf)

        """
        ftpfile = os.path.join(tmpdir, "ftp.log")
        if os.path.exists(ftpfile):
            __parse_ftp_file(resp, ftpfile, network_conf)
        """

        # Finally, process file extraction and analysis. Note that our BRO script will take care
        # of extracting files into a subdirectory named extracted_files.
        filefile = os.path.join(tmpdir, "files.log")
        if os.path.exists(filefile):
            __parse_file_file(resp, filefile, network_conf)

    finally:
        # Remove temp stuff
        shutil.rmtree(tmpdir)


def __parse_file_file(resp,filefile,network_conf):
    log.info("Analyzing files file, network_conf %s" % str(network_conf))
    # This function takes care of analyzing extracted files. Bro takes care of extracting files into a local
    # directory and also calculates SHA1 and MD5 for top level files detected. Here, we need to add some more info
    # about files we encounter. In particular, we want to recursively extract them in order to obtain a table
    # of SOURCE_IP / DOMAIN / PROTOCOL / CONVERSATION <-> FILE_HASH / TYPE / MIME / PARENT.

    with open(filefile, "r") as f:
        for l in f:
            record = json.loads(l)
            for i in network_conf['guest_ip']:
                record['tx_hosts'] = ['GUEST_IP' if str(i) == str(x) else 'DEFAULT_GW' if str(x) == str(network_conf['default_gw']) else x for x in record['tx_hosts']]
                if str(i) in record['tx_hosts']:
                    record['direction'] = "OUTBOUND"

                record['rx_hosts'] = ['GUEST_IP' if str(i) == str(x) else 'DEFAULT_GW' if str(x) == str(network_conf['default_gw']) else x for x in record['rx_hosts']]
                if str(i) in record['rx_hosts']:
                    record['direction'] = "INBOUND"

            # Now let's gather file path, its hash and try to recursively unzip it.
            ext = record['extracted']
            directory = os.path.dirname(os.path.abspath(filefile))
            fpath = os.path.join(directory, "extract_files", ext)
            str_fuzzy = ssdeep.hash_from_file(fpath)
            record['fuzzy'] = str_fuzzy
            _analyze_compressed_file(parent=None, node=record, path=fpath, nesting_level=0)
            resp['files'].append(record)


def __parse_http_file(resp,httpfile,network_conf):
    with open(httpfile, "r") as f:
        for l in f:
            record = json.loads(l)

            # We are just interested in HIGH LEVEL information, because most of L4 info is logged into the conn
            # file. So we need to filter only relevant info from this log.
            for i in network_conf['guest_ip']:
                if record['id.orig_h'] == str(i) or record['id.orig_h'] == "0.0.0.0":
                    record['direction'] = "OUTBOUND"
                    break
                elif record['id.resp_h'] == str(i):
                    record['direction'] = "INBOUND"
                    break

            if record['id.orig_h'] == network_conf['default_gw']:
                record['id.orig_h'] = "DEFAULT_GW"
            if record['id.resp_h'] == network_conf['default_gw']:
                record['id.resp_h'] = "DEFAULT_GW"

            for i in network_conf['guest_ip']:
                if record['id.orig_h'] == str(i):
                    record['id.orig_h'] = "GUEST_IP"
                    break
                if record['id.resp_h'] == str(i):
                    record['id.resp_h'] = "GUEST_IP"
                    break

            resp['http'].append(record)


def __parse_dns_file(resp,dnsfile,network_conf):
    with open(dnsfile, "r") as f:
        for l in f:
            record = json.loads(l)

            # We are just interested in HIGH LEVEL information, because most of L4 info is logged into the conn
            # file. So we need to filter only relevant info from this log.
            for i in network_conf['guest_ip']:
                if record['id.orig_h'] == str(i) or record['id.orig_h'] == "0.0.0.0":
                    record['direction'] = "OUTBOUND"
                    break
                elif record['id.resp_h'] == str(i):
                    record['direction'] = "INBOUND"
                    break

            if record['id.orig_h'] == network_conf['default_gw']:
                record['id.orig_h'] = "DEFAULT_GW"
            if record['id.resp_h'] == network_conf['default_gw']:
                record['id.resp_h'] = "DEFAULT_GW"

            for i in network_conf['guest_ip']:
                if record['id.orig_h'] == str(i):
                    record['id.orig_h'] = "GUEST_IP"
                    break
                if record['id.resp_h'] == str(i):
                    record['id.resp_h'] = "GUEST_IP"
                    break

            resp['dns'].append(record)


def __parse_conn_file(resp, connfile, network_conf):
    with open(connfile, "r") as f:
        for l in f:
            record = json.loads(l)

            # We need to manipulate each record in order to facilitate further analysis.
            # For instance, we detect the direction of each conversation looking at the IP addresses
            # listed in the origin IP and resp IP. If origin IP matches our client's IP, then that is an
            # OUTGOING connection. Otherwise, if resp IP matches our client's IP, than we classify that
            # flow as incoming. We also want to use a marker for DEFAULT GATEWAY, since this may depend
            # on specific network configuration.
            for i in network_conf['guest_ip']:
                if record['id.orig_h'] == str(i) or record['id.orig_h'] == "0.0.0.0":
                    record['direction'] = "OUTBOUND"
                    break
                elif record['id.resp_h'] == str(i):
                    record['direction'] = "INBOUND"
                    break
            if record.get('direction') is None:
                record['direction'] = "UNKNOWN"

            if record['id.orig_h'] == network_conf['default_gw']:
                record['id.orig_h'] = "DEFAULT_GW"
            if record['id.resp_h'] == network_conf['default_gw']:
                record['id.resp_h'] = "DEFAULT_GW"

            for i in network_conf['guest_ip']:
                if record['id.orig_h'] == str(i):
                    record['id.orig_h'] = "GUEST_IP"
                    break
                if record['id.resp_h'] == str(i):
                    record['id.resp_h'] = "GUEST_IP"
                    break

            resp['conversations'].append(record)

            protocol = record['proto']
            service = record['service']

            # Classify by protocol.
            l4 = resp['protocols'].get(protocol)
            if l4 is None:
                l4 = dict()
                l4['outbound_pkts'] = 0
                l4['outbound_bytes'] = 0
                l4['inbound_pkts'] = 0
                l4['inbound_bytes'] = 0

                # IP Level
                l4['outbound_ip_pkts'] = 0
                l4['outbound_ip_bytes'] = 0
                l4['inbound_ip_pkts'] = 0
                l4['inbound_ip_bytes'] = 0
                resp['protocols'][protocol] = l4

            l7 = l4.get(service)
            if l7 is None:
                l7 = dict()

                # Payloads
                l7['outbound_pkts'] = 0
                l7['outbound_bytes'] = 0
                l7['inbound_pkts'] = 0
                l7['inbound_bytes'] = 0

                # IP Level
                l7['outbound_ip_pkts'] = 0
                l7['outbound_ip_bytes'] = 0
                l7['inbound_ip_pkts'] = 0
                l7['inbound_ip_bytes'] = 0

                resp['protocols'][protocol][service] = l7

            # Update L7 statistics
            if record['direction'] == "OUTBOUND" or record['direction'] == "UNKNOWN":
                l7['outbound_pkts'] += record.get('orig_pkts',0)
                l7['outbound_bytes'] += record.get('orig_bytes',0)
                l7['inbound_pkts'] += record.get('resp_pkts',0)
                l7['inbound_bytes'] += record.get('resp_bytes',0)

                # IP Level
                l7['outbound_ip_pkts'] += record.get('orig_ip_pkts',0)
                l7['outbound_ip_bytes'] += record.get('orig_ip_bytes',0)
                l7['inbound_ip_pkts'] += record.get('resp_ip_pkts',0)
                l7['inbound_ip_bytes'] += record.get('resp_ip_bytes',0)

                # Also update L4 statistics
                l4['outbound_pkts'] += record.get('orig_pkts',0)
                l4['outbound_bytes'] += record.get('orig_bytes',0)
                l4['inbound_pkts'] += record.get('resp_pkts',0)
                l4['inbound_bytes'] += record.get('resp_bytes',0)

                # IP Level
                l4['outbound_ip_pkts'] += record.get('orig_ip_pkts',0)
                l4['outbound_ip_bytes'] += record.get('orig_ip_bytes',0)
                l4['inbound_ip_pkts'] += record.get('resp_ip_pkts',0)
                l4['inbound_ip_bytes'] += record.get('resp_ip_bytes',0)

            elif record['direction'] == "INBOUND":
                l7['inbound_pkts'] += record.get('orig_pkts',0)
                l7['inbound_bytes'] += record.get('orig_bytes',0)
                l7['outbound_pkts'] += record.get('resp_pkts',0)
                l7['outbound_bytes'] += record.get('resp_bytes',0)

                # IP Level
                l7['inbound_ip_pkts'] += record.get('orig_ip_pkts',0)
                l7['inbound_ip_bytes'] += record.get('orig_ip_bytes',0)
                l7['outbound_ip_pkts'] += record.get('resp_ip_pkts',0)
                l7['outbound_ip_bytes'] += record.get('resp_ip_bytes',0)

                # Also update L4 statistics
                l4['inbound_pkts'] += record.get('orig_pkts',0)
                l4['inbound_bytes'] += record.get('orig_bytes',0)
                l4['outbound_pkts'] += record.get('resp_pkts',0)
                l4['outbound_bytes'] += record.get('resp_bytes',0)

                # IP Level
                l4['inbound_ip_pkts'] += record.get('orig_ip_pkts',0)
                l4['inbound_ip_bytes'] += record.get('orig_ip_bytes',0)
                l4['outbound_ip_pkts'] += record.get('resp_ip_pkts',0)
                l4['outbound_ip_bytes'] += record.get('resp_ip_bytes',0)

            # TODO: what if direction is different?

def _analyze_compressed_file(parent, node, path, nesting_level):
    m_type = mime.from_file(path)
    size = os.path.getsize(path)

    m = md5()
    s = sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            m.update(chunk)
            s.update(chunk)

    str_md5 = m.hexdigest()
    str_sha1 = s.hexdigest()

    str_fuzzy = ssdeep.hash_from_file(path)

    node['filename'] = os.path.basename(path)
    node['mime_type'] = m_type
    node['size'] = size
    node['md5'] = str_md5
    node['sha1'] = str_sha1
    node['fuzzy'] = str_fuzzy
    node['nesting_level'] = nesting_level+1
    str_fuzzy = ssdeep.hash_from_file(path)
    node['fuzzy'] = str_fuzzy
    if parent is None:
        node['parent_hash'] = None
    else:
        node['parent_hash'] = parent.get('sha1')

    node['compressed_children'] = []

    # If this is a compressed file, analyze it recursively. This means we need to create a new directory, uncompress
    # files there and calculate hashes. Then, delete the extracted files when done.
    # zip, x-tar, x-7z-compressed, x-rar, vnd.ms-cab-compressed, gzip, x-bzip2, x-7z-compressed
    tmpdir = tempfile.mkdtemp()
    try:
        # Brute force approach: we don't even check the mime file. We try to unpack evey archive.
        # Extract all the files
        patoolib.extract_archive(path, outdir=tmpdir)

        # Analyze each file
        files = [os.path.join(tmpdir,f) for f in os.listdir(tmpdir) if os.path.isfile(os.path.join(tmpdir, f))]
        for f in files:
            child=dict()
            _analyze_compressed_file(parent=node, node=child, path=f, nesting_level=nesting_level+1)
            node['compressed_children'].append(child)
    except:
        pass
    finally:
        # Remove the temporary file directory
        shutil.rmtree(tmpdir)


def iterative_server(host, port):
    # First step: allocate the server socket

    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    serversocket.bind((host, port))
    # We will be an iterative server, so refuse connections if there is no time to process them.
    serversocket.listen(0)
    # Put the socket in Blocking mode. We will never raise timeout exception if none is
    # connecting to us
    serversocket.settimeout(None)

    # Start service requests
    ct = None
    while 1:
        try:
            log.debug("Waiting for a connection...")
            (ct, address) = serversocket.accept()
            set_keepalive_linux(ct)

            # Here we care about socket timeout. If client crashes for some reason, we should recover quickly
            ct.settimeout(GENERAL_TIMEOUT)
            log.debug("Received connection from %s:%d" % address)

            # Now we receive both files
            with tempfile.NamedTemporaryFile() as pcapfp:  # note: this won't work correctly on windows!
                with tempfile.NamedTemporaryFile() as httpsfile:  # note: this won't work correctly on windows!
                    def _recv(s, datalen):
                        tot = 0
                        res = []
                        while tot<datalen:
                            buf = s.recv(datalen)
                            if not buf:
                                raise Exception("Cannot read from socket, socket might be closed.")

                            tot += len(buf)
                            res.append(buf)

                        return ''.join(res)

                    def recv_file(s, fp):
                        # Receive file dimension for network capture file
                        torecv = struct.calcsize('!L')
                        data = _recv(s,torecv)
                        size = struct.unpack('!L', data)[0]

                        log.debug("Expecting %d bytes for capture file." % size)

                        received = 0
                        while received < size:
                            din_buf_size = BUFFLEN
                            if (size-received) < BUFFLEN:
                                din_buf_size = size-received
                            data = ct.recv(din_buf_size)
                            if data:
                                received += len(data)
                                fp.write(data)
                            else:
                                raise Exception("Error when receiving data.")
                        fp.flush()

                    def recv_conf(s):
                        # Receive string length
                        torecv = struct.calcsize('!L')
                        data = _recv(s,torecv)
                        size = struct.unpack('!L', data)[0]

                        log.debug("Expecting %d bytes for conf dictionary." % size)

                        data = _recv(s,size)

                        return json.loads(data)

                    recv_file(ct, pcapfp)
                    recv_file(ct, httpsfile)
                    network_conf = recv_conf(ct)

                    """
                    # TODO: change me!
                    network_conf = dict()
                    network_conf['sniffer_hostname'] = 'www.sniffer.net'
                    network_conf['hc_ip'] = "192.168.56.1"
                    network_conf['hc_port'] = 9000
                    network_conf['guest_ip'] = "192.168.0.88"
                    network_conf['default_gw'] = "192.168.0.1"
                    """

                    log.debug("Received both analysis files. Processing analysis...")

                    # Now analyze pcap file first.
                    result = dict()

                    # Dictionary are mutable object in python, so we get the abstraction of pass-by-reference here.
                    analyse_pcap(result, pcapfp.name, network_conf)
                    analyse_https(result, httpsfile.name)

                    # We send data until we have, then we close the socket. The client knows that means end of data.
                    log.debug("Analysis completed. Sending it back")
                    data = json.dumps(result)

                    ct.sendall(data)

                    ct.shutdown(socket.SHUT_RDWR)
                    log.debug("Done!")

        except Exception as e:
            log.exception("Error when serving analysis.")
        finally:
            if ct is not None:
                ct.close()


def start(host, port):
    log.info("Starting server on %s:%d" % (host, port))
    # Create the server, binding to localhost on port 9999
    server_thread = threading.Thread(target=iterative_server, args=(host, port))
    server_thread.start()


def set_keepalive_linux(sock, after_idle_sec=1, interval_sec=3, max_fails=5):
    """Set TCP keepalive on an open socket.

    It activates after 1 second (after_idle_sec) of idleness,
    then sends a keepalive ping once every 3 seconds (interval_sec),
    and closes the connection after 5 failed ping (max_fails), or 15 seconds
    """
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle_sec)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval_sec)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)