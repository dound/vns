# define Django-related settings
import django_settings

# IP of the server this simulator works for
VNS_WEB_SERVER_IP = 'localhost'

# Whether to forward packets addressed to 10/8, 172.16/12, or 192.168/16
# addresses out to the network (off of the simulator).  This does not affect
# forwarding within the simulation.
MAY_FORWARD_TO_PRIVATE_IPS = True
