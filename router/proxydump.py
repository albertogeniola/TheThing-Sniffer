from multiprocessing import Process
import signal
import os
from mitmproxy import controller, proxy
from mitmproxy import dump, options
from mitmproxy.proxy.server import ProxyServer


def _run(port, outfile, mode, cadir):
    opts = options.Options(listen_port=port, mode=mode, cadir=cadir)
    config = proxy.ProxyConfig(opts)
    server = ProxyServer(config)
    m = dump.DumpMaster(server, dump.Options(outfile=[outfile,'wb'], verbosity=0))

    # Define a handler for the shutdown signal so the parent process knows how to stop me
    def cleankill(*args, **kwargs):
        m.shutdown()
    signal.signal(signal.SIGTERM, cleankill)

    # Now start the server. This operation will block.
    m.run()


class MitmSnifferInstance(object):
    _port = None
    _outfile = None
    _mode = None
    _cadir = None
    _proc = None

    def __init__(self, port, outfile, mode, cadir):
        self._port = port
        self._outfile = outfile
        self._mode = mode
        self._cadir = cadir
        self._proc = Process(target=_run, args=(self._port, self._outfile, self._mode, self._cadir))

    def start(self):
        self._proc.start()

    def stop(self):
        # Send the sigterm and wait
        os.kill(self._proc.pid, signal.SIGTERM)

        # Wait until it exists
        self._proc.join()