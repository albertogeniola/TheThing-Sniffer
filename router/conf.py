# Name of the NIC on which TCPDUMP and MITMPROXY should listen on. This device must exist in /etc/network/interfaces and must be the one connected to the internal network, where sandboxes are connected.
CAPTURE_IF = "eth1"

# TCPDUMP command to be issued on the shell. If tcpdumop is not in the $PATH, the user has to specify the full path to TCPDUMP
TCPDUMP_EX = "tcpdump"

# Maximum capture file size (in Megabytes) for each experiment. Increase this number in accordance with the number of tcpinstance to run. Be advised: no check is performed against the disk usage. Keep this number reasonably low.
MAX_PCAP_SIZE = 2048

# Location where capture files will be stored during the sniffing sessions
PCAP_FOLDER_PATH = "/var/caps"

# Path where the MITMPROXY certificate resides
CA_DIR = "/etc/router/certs"

# IPTABLES command issued aimed at intercepting SSL traffic via MITMPROXY on port 443
COMMAND = 'iptables -w -t nat %s PREROUTING -i %s -m mac --mac-source %s -p tcp --dport 443 -j REDIRECT --to-port %d'

# Path to the directory where the sniffer stores GuestAgents to be served to clients
AGENT_CLIENT_DIR = "/var/sandbox_clients"

# The following two lines are used to configure the broadcast receiver which is in charge of serving GuestAgents to the Bootstrappers.
BDCAST_RECEIVER_ADDR = "0.0.0.0"
BDCAST_RECEIVER_PORT = 9000

# Port on which the webservice listens to.
WEB_SERVICE_PORT = 8080

import logging
LOG_LEVEL = logging.DEBUG
