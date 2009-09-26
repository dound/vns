from os import environ

# tell Django about the Django settings file
environ['DJANGO_SETTINGS_MODULE'] = 'web.settings'

# IP of the server this simulator works for
VNS_WEB_SERVER_IP = 'localhost'

# location where the VNS web server will listen
VNS_WEB_SERVER_PORT = 80

# Whether to forward packets addressed to 10/8, 172.16/12, or 192.168/16
# addresses out to the network (off of the simulator).  This does not affect
# forwarding within the simulation.
MAY_FORWARD_TO_PRIVATE_IPS = True

# The interface which connects the simulator to the real network.  All packets
# will be sniffed from this interface.  If the packet is addressed to one of the
# simulated topology's Ethernet addresses (or is an ARP request for the Ethernet
# address of one its gateway node IPs), then it will be injected onto the
# appropriate topology.  Packets coming off simulated topology's will be put out
# on this interface.  If it is the empty string, then the similar is isolated.
BORDER_DEV_NAME = 'eth0'

# The list of IPs to NOT inject from the real world to the simulator.  Usually,
# you want the simulator machine's own IP address to be in this list.
IP_ADDRS_TO_FILTER_OUT = ['']

# The filter describing what packets to inject from those sniffed from the real
# world.  The default is to inject everything except IP packets to or from
# addresses in the IP_ADDRS_TO_FILTER_OUT list.
PCAP_FILTER = ' and '.join(['not ip dst %s and not ip src %s' % (a,a) for a in IP_ADDRS_TO_FILTER_OUT])
