"""Defines a simple VNS-like simulation."""

import struct

from twisted.internet import reactor

from VNSProtocol import VNS_DEFAULT_PORT, create_vns_server
from VNSProtocol import VNSOpen, VNSClose, VNSPacket, VNSInterface, VNSHardwareInfo

class Node:
    """A node in a topology"""
    def __init__(self, name, interfaces):
        self.name = name
        self.interfaces = interfaces
        for intf in self.interfaces:
            intf.owner = self
            intf.neighboring_interfaces = []

    def has_connection(self, _):
        return False

    def send_packet(self, departing_intf, packet):
        for intf in departing_intf.neighboring_interfaces:
            intf.owner.handle_packet(intf, packet)

class VirtualNode(Node):
    """A node which a user can take control of (i.e., handle packets for)"""
    def __init__(self, name, interfaces):
        Node.__init__(self, name, interfaces)
        self.conn = None  # connection to the virtual host, if any

    def connect(self, conn):
        if self.conn is not None:
            print 'Terminating the old control connection to %s - reconnected' % self.name
        self.conn = conn
        return True

    def has_connection(self, conn):
        return self.conn == conn

    def disconnect(self, conn):
        self.conn = None
        conn.loseConnection()
        print '%s is now free - client disconnected with VNSClose message' % self.name

    def handle_packet(self, intf, packet):
        """Forwards to the user responsible for handling packets for this virtual node"""
        if self.conn is not None:
            self.conn.send(VNSPacket(intf.name, packet))

class Host(Node):
    """A host in the network which replies to echo requests"""
    def __init__(self, name, interfaces):
        Node.__init__(self, name, interfaces)

    def connect(self, _):
        print 'Rejecting connection to %s - may not control a Host node' % self.name
        return False

    def handle_packet(self, intf, packet):
        """Replies to echo requests"""
        eth_type = struct.unpack('> H', packet[12:14])[0]
        if eth_type == 0x0800:
            ip_proto = struct.unpack('> B', packet[23:24])[0]
            if ip_proto == 1:
                icmp_type = struct.unpack('> B', packet[34:35])[0]
                if icmp_type == 8:
                    eth = packet[6:12] + packet[0:6] + packet[12:14]   # reverse MAC SA, DA
                    ip = packet[14:26] + packet[30:34] + packet[26:30] # reverse IP SA, DA
                    icmp = struct.pack('> B', 0) + packet[31:]         # change to echo reply type
                    echo_reply = eth + ip + icmp
                    self.send_packet(intf, echo_reply)

class Hub(Node):
    """A hub"""
    def __init__(self, name, interfaces):
        Node.__init__(self, name, interfaces)

    def connect(self, _):
        print 'Rejecting connection to %s - may not control a Hub node' % self.name
        return False

    def handle_packet(self, incoming_intf, packet):
        """Forward each received packet to every interface except the one it was received on"""
        for intf in self.interfaces:
            if intf.name != incoming_intf.name:
                self.send_packet(intf, packet)

def make_ip(a):
    """Creates an IP from a string representation"""
    octets = a.split('.')
    return int(octets[0]) << 24 |\
           int(octets[1]) << 16 |\
           int(octets[2]) <<  8 |\
           int(octets[3])

def make_mac(i, intf_num):
    """Creates the MAC address 00:00:00:00:i:intf_num"""
    return struct.pack('> 6B', 0, 0, 0, 0, i, intf_num)

class Topology:
    """Builds and stores a topology"""
    def __init__(self):
        def make_rtr_interfaces(i):
            a = i
            b = 4 if i==1 else i-1
            return [
                VNSInterface('eth0', make_mac(i, 0), make_ip('192.168.%u.%u' %(i,i)), make_ip('255.255.255.0')),
                VNSInterface('eth1', make_mac(i, 1), make_ip('10.%u.0.%u  '  %(a,i)), make_ip('255.255.0.0')),
                VNSInterface('eth2', make_mac(i, 2), make_ip('10.0.0.%u'     %i),     make_ip('255.255.0.0')),
                VNSInterface('eth3', make_mac(i, 3), make_ip('10.%u.0.%u'    %(b,i)), make_ip('255.255.0.0'))
                ]

        def make_host_interfaces(i):
            return [VNSInterface('eth0', make_mac(i, 9), make_ip('192.168.%u.9' %i), make_ip('255.255.255.0'))]

        # create the interfaces for our routers and hosts (1 indexed)
        n = 4
        rng = range(1, n+1)
        rtr_interfaces = [None] + [make_rtr_interfaces(i) for i in rng]
        host_interfaces = [None] + [make_host_interfaces(i) for i in rng]

        # create the virtual nodes (routers) and hosts in the topology
        vnodes = [VirtualNode('rtr%u'%i, rtr_interfaces[i]) for i in rng]
        hosts = [Host('host%u'%i, host_interfaces[i]) for i in rng]

        # create the hub (note: interfaces don't have MACs/IPs - just names)
        hub_interfaces = [VNSInterface('eth%u' % i, '000000', 0, 0) for i in rng]
        hub = Hub('hub', hub_interfaces)

        # connect interfaces
        def connect_intfs(intf1, intf2):
            intf1.neighboring_interfaces.append(intf2)
            intf2.neighboring_interfaces.append(intf1)

        for i in rng:
            # connect router eth0 to host eth0
            connect_intfs(rtr_interfaces[i][0], host_interfaces[i][0])

            # connect router eth1 to the next router's eth3
            i2 = 1 if i==4 else i+1
            connect_intfs(rtr_interfaces[i][1], rtr_interfaces[i2][3])

            # connect router eth2 to the hub
            connect_intfs(hub_interfaces[i-1], rtr_interfaces[i][2])

        # store a list of all nodes in the topology
        self.nodes = vnodes + hosts + [hub]

class SimpleVNS:
    """Handles incoming messages from each client"""
    def __init__(self):
        self.topo = Topology()
        self.server = create_vns_server(VNS_DEFAULT_PORT, self.handle_recv_msg)

    def handle_recv_msg(self, conn, vns_msg):
        if vns_msg is not None:
            print 'recv: %s' % str(vns_msg)
            if vns_msg.get_type() == VNSOpen.get_type():
                self.handle_open_msg(conn, vns_msg)
            elif vns_msg.get_type() == VNSClose.get_type():
                self.handle_close_msg(conn)
            elif vns_msg.get_type() == VNSPacket.get_type():
                self.handle_packet_msg(conn, vns_msg)

    def handle_open_msg(self, conn, open_msg):
        requested_name = open_msg.vhost.replace('\x00', '')
        for n in self.topo.nodes:
            if n.name == requested_name:
                if n.connect(conn):
                    conn.send(VNSHardwareInfo(n.interfaces))
                else:
                    conn.loseConnection()  # failed to connect
                return


        # failed to find the requested node
        print 'unknown node name requested: %s' % requested_name
        conn.loseConnection()

    def handle_close_msg(self, conn):
        for n in self.topo.nodes:
            if n.has_connection(conn):
                n.disconnect()
                return

    def handle_packet_msg(self, conn, pkt_msg):
        for n in self.topo.nodes:
            if n.conn == conn:
                departure_intf_name = pkt_msg.intf_name.replace('\x00', '')
                for intf in n.interfaces:
                    if intf.name == departure_intf_name:
                        n.send_packet(intf, pkt_msg.ethernet_frame)
                        return

                # failed to find the specified interface
                print 'bad packet request on node %s: invalid interface: %s' % (n.name, departure_intf_name)
                return

        # failed to find the specified connection?!?
        print 'Unable to find the node associated with this connection??  Disconnecting it: %s' % str(conn)
        conn.loseConnection()

def main():
    SimpleVNS()
    reactor.run()

if __name__ == "__main__":
    main()
