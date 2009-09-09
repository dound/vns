# define Django-related settings
import django_settings

# IP of the server this simulator works for
VNS_WEB_SERVER_IP = 'localhost'

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
