"""The VNS simulator."""

import logging.config
import random
from socket import inet_ntoa
import struct

from pcapy import open_live
from twisted.internet import reactor

import settings
import web.vns.models as db
from VNSProtocol import VNS_DEFAULT_PORT, create_vns_server
from VNSProtocol import VNSOpen, VNSClose, VNSPacket, VNSInterface, VNSHardwareInfo

logging.config.fileConfig('logging.conf')

class ConnectionReturn():
    def __init__(self, fail_reason=None, prev_client=None):
        self.fail_reason = fail_reason
        self.prev_client = prev_client

    def is_success(self):
        return self.fail_reason is None

class Topology():
    """A topology to simulate."""
    def __init__(self, tid):
        """Reads topology with the specified id from the database.  A
        DoesNotExist exception (Topology or IPAssignment) is raised if this fails."""
        # maps clients connected to this topology to the node they are connected to
        self.clients = {}

        t = db.Topology.objects.get(pk=tid)
        self.id = tid

        # read in this topology's nodes
        db_nodes = db.Node.objects.filter(template=t.template)
        self.gateway = None
        self.nodes = [self.__make_node(dn) for dn in db_nodes]

        # remember the DB to simulator object mapping
        nodes_db_to_sim = {}
        for i in range(len(db_nodes)):
            dn = db_nodes[i]
            sn = self.nodes[i]
            nodes_db_to_sim[dn] = sn

        # read in this topology's ports
        interfaces_db_to_sim = {}
        db_ports = db.Port.objects.filter(node__template=t.template)
        for dp in db_ports:
            sn = nodes_db_to_sim[dp.node]
            ipa = db.IPAssignment.objects.get(topology=t, port=dp)
            intf = sn.add_interface(dp.name, ipa.get_mac(), ipa.get_ip(), ipa.get_mask())
            interfaces_db_to_sim[dp] = intf

        # read in this topology's links
        links = Link.objects.filter(port1__node__template=t.template)
        for db_link in links:
            intf1 = interfaces_db_to_sim[db_link.port1]
            intf2 = interfaces_db_to_sim[db_link.port2]
            Link(intf1, intf2, db_link.lossiness)

        # determine who may use this topology
        tus = db.TopologyUser.objects.filter(topology=t)
        self.permitted_user_ips = [tu.ip for tu in tus]

    def connect_client(self, client_conn, requested_name):
        """Called when a user tries to connect to a node in this topology.
        Returns True if the requested node exists and the client was able to
        connect to it.  Otherwise it returns an error message."""
        for n in self.nodes:
            if n.name == requested_name:
                self.clients[client_conn] = n
                ret = n.connect(client_conn)
                if ret.is_success():
                    client_conn.send(VNSHardwareInfo(n.interfaces))
                    fmt = 'client (%s) has connected to topology %d node %s'
                    logging.info(fmt % (client_conn, self.id, n))
                return ret
        return ConnectionReturn('there is no node named %s' % requested_name)

    def client_disconnected(self, client_conn):
        n = self.clients.pop(client_conn)
        n.disconnect(client_conn)

    def get_gateway_addrs(self):
        """Returns a list of Ethernet and IP addresses (as byte-strings) which
        belong to gateways (if any) connecting this topology to the outside."""
        addrs = []
        sz = len(self.gateway.interfaces)
        if sz > 1:
            logging.error('gateway in topology %d has more than 1 interface' % self.id)

        if sz > 0:
            intf = self.gateway.interfaces[0]
            if intf.link:
                other = intf.link.get_other()
                addrs.append(other.mac)
                addrs.append(struct.pack('>I', other.ip))
        return addrs

    def get_id(self):
        """Returns this topology's unique ID number."""
        return self.id

    def handle_packet_from_client(self, conn, pkt_msg):
        """Sends the specified message out the specified port on the node
        controlled by conn.  If conn does not control a node, then a KeyError is
        raised.  If conn's node does not have an interface with the specified
        name then an error message is returned.  Otherwise, True is returned."""
        departure_intf_name = pkt_msg.intf_name.replace('\x00', '')
        n = self.clients[conn]
        for intf in n.interfaces:
            if intf.name == departure_intf_name:
                n.send_packet(intf, pkt_msg.ethernet_frame)
                return True

        # failed to find the specified interface
        fmt = 'bad packet request: invalid interface: %s'
        return fmt % (n.name, departure_intf_name)

    def handle_packet_to_gateway(self, packet):
        """Forwards packet to the node connected to the gateway."""
        if len(self.gateway.interfaces) > 0:
            intf = self.gateway.interfaces[0]
            if intf.link:
                intf.link.send_to_other(intf, packet)

    def is_active(self):
        """Returns true if any clients are connected."""
        return len(self.clients) > 0

    def __make_node(self, dn):
        """Converts the given database node into a simulator node object."""
        # TODO: need to distinguish between nodes THIS simulator simulates,
        #       versus nodes which ANOTHER simulator is responsible for.  Do
        #       this with a RemotelySimulatedNode class which handles received
        #       packets by forwarding them to the appropriate simulator.
        if dn.type == db.Node.VIRTUAL_NODE_ID:
            return VirtualNode(dn.name)
        elif dn.type == db.Node.BLACK_HOLE_ID:
            return BlackHole(dn.name)
        elif dn.type == db.Node.HUB_ID:
            return Hub(dn.name)
        elif dn.type == db.Node.WEB_SERVER_ID:
            return WebServer(dn.name)
        elif dn.type == db.Node.GATEWAY_ID:
            if self.gateway is not None:
                err = 'only one gateway per topology is allowed'
            else:
                self.gateway = Gateway(dn.name)
                return self.gateway
        else:
            err = 'unknown node type: %d' % dn.type
        logging.critical(err)
        raise db.Topology.DoesNotExist(err)

class Link:
    """Information about a connection between two ports.  Tells intf1 and intf2
    about this link too."""
    def __init__(self, intf1, intf2, lossiness):
        self.intf1 = intf1
        self.intf2 = intf2
        self.lossiness = lossiness

        # double-check that both ports are currently empty
        if self.__is_link_set(intf1) and self.__is_link_set(intf2):
            intf1.link = self
            intf2.link = self

    def __is_link_set(self, intf):
        """Checks to see if intf has a link plugged in.  If it does, a warning
        is logged."""
        if intf.link:
            fmt = 'interface %s on %s has two links: %s and %s'
            logging.warning(fmt % (intf, intf.owner, intf.link, self))
            return False
        else:
            return True

    def get_other(self, intf):
        """Gets the other interface attached to this link."""
        if self.intf1 == intf:
            return self.intf2
        elif self.intf2 == intf:
            return self.intf1
        else:
            msg = 'intf %s is neither intf1 (%s) or intf2 (%2)' % (intf, self.intf1, self.intf2)
            logging.critical(msg)
            raise RuntimeError(msg)

    def send_to_other(self, intf_from, packet):
        """Sends the packet out of the specified interface.  This triggers
        handle_packet() to be called on the owner of the receiving interface.
        The packet may be randomly discarded if lossiness is greater than zero."""
        if self.lossiness==0.0 or random.random()>self.lossiness:
            self.get_other(intf_from).owner.handle_packet(intf_from, packet)

class Node:
    """A node in a topology"""
    def __init__(self, name):
        self.name = name
        self.interfaces = []

    def add_interface(self, name, mac, ip, mask):
        """Adds an interface to this node.  mac, ip, and mask must be in
         network-byte order.  The new interface is returned."""
        intf = VNSInterface(name, mac, ip, mask)
        intf.owner = self
        intf.link = None  # will be set by Link.__init__() if connected to another port
        self.interfaces.append(intf)
        return intf

    def connect(self, conn):
        """Called when a user tries to connect to this node.  Returns a
        ConnectionReturn object to describe the result."""
        fmt = 'Rejecting connection to %s - may not control a %s node'
        msg = fmt % (self.name, self.get_type_str())
        return ConnectionReturn(msg)

    def disconnect(self, conn):
        pass

    @staticmethod
    def get_type_str():
        """Returns a string which describes what kind of node this is."""
        return 'Undefined Node'

    def has_connection(self, _):
        """Returns true if a user is connected to this Node."""
        return False

    def has_ip(self, ip):
        """Returns whether ip is assigned to any of this node's interfaces.  ip
        should be a network byte-order integer."""
        for intf in self.interfaces:
            if intf.ip == ip:
                return True
        return False

    def send_packet(self, departing_intf, packet):
        """Sends the packet out departing_intf."""
        if departing_intf.link:
            departing_intf.link.send_to_other(departing_intf, packet)

class BasicNode(Node):
    """A basic node which replies to ARP and ICMP Echo requests.  Further
    handling of IP packets is delegated to subclasses."""
    def __init__(self, name):
        Node.__init__(self, name)

    @staticmethod
    def get_type_str():
        return 'Undefined Basic Node'

    def handle_packet(self, intf, packet):
        """Responses to ARP requests (as appropriate) and forwards IP packets."""
        if len(packet) < 14:
            logging.debug('ignoring packet which is too small: %dB' % len(packet))
            return

        eth_type = struct.unpack('> H', packet[12:14])[0]
        if eth_type == 0x0800:
            self.handle_ip_packet(intf, packet[:14], packet[14:])
        elif eth_type == 0x0806:
            self.handle_arp_packet(intf, packet[:14], packet[14:])

    def handle_arp_packet(self, intf, eth, arp):
        """Respond to arp if it is a request for the mac address of intf's IP."""
        if len(arp) < 28:            # must be the expected size
            logging.debug('ignoring ARP packet which is too small: %dB (%dB incl the Ethernet frame)' % (len(arp), len(eth)+len(arp)))
            return
        elif arp[6:8] != '\x00\x01': # must be ARP REQUEST
            return
        elif arp[0:2] != '\x00\x01': # must be Ethernet HW type
            return
        elif arp[2:4] != '\x08\x00': # must be IP protocol type
            return
        elif arp[4]   != '\x06':     # must be 6B Ethernet address
            return
        elif arp[5]   != '\x04':     # must be 4B IP address
            return

        # get the source and destination hw and protocol addrs
        sha = arp[8:14]
        spa = arp[14:18]
        dha = arp[18:24]
        dpa = arp[24:28]

        # is the ARP request asking about THIS interface on broadcast dha?
        intf_ip_packed = struct.pack('> I', intf.ip)
        if intf_ip_packed == dpa and dha=='\xFF\xFF\xFF\xFF\xFF\xFF':
            # send it back to the requester (reverse src/dst, copy in our mac addr)
            reply_eth = eth[6:12] + eth[0:6] + eth[12:14]   # reverse MAC SA, DA
            reply_arp = arp[0:8] + intf.mac + intf_ip_packed + sha + spa # rev for reply
            self.send_packet(intf, reply_eth + reply_arp)

    def handle_ip_packet(self, intf, eth, ip):
        """Vets an IP packet's size and version, and replying if it is an ICMP
        echo request.  Other handling is delegated to subclasses.  If the size
        is too small or the version is wrong, it will be discarded."""
        if len(ip) < 20:            # must be the expected size
            logging.debug('ignoring IP packet which is too small: %dB (%dB incl the Ethernet frame)' % (len(ip), len(eth)+len(ip)))
            return

        ver = (struct.unpack('> B', ip[0]) & 0xF0) >> 4
        if ver != 4:
            logging.debug('ignoring non-IPv4 packet: v=%d' % ver)
            return

        dst_ip = struct.unpack('> I', ip[16:20])
        if self.has_ip(dst_ip):
            self.handle_ip_packet_to_self(intf, eth, ip)
        else:
            self.handle_ip_packet_to_other(intf, eth, ip)

    def handle_ip_packet_to_self(self, intf, eth, ip):
        """Called when a IP packet for on of our interfaces is received on intf.
        eth holds the Ethernet frame bytes and ip holds the IP packet bytes.
        This implementation replies with an echo reply or protocol unreachable
        as appropriate."""
        proto = ip[9]
        if proto == '\x01':
            icmp = ip[20:]
            if icmp[0] == '\x08':
                new_eth = eth[6:12] + eth[0:6] + eth[12:14] # reverse MAC SA, DA
                new_ip = ip[0:12] + ip[16:20] + ip[12:16]   # reverse IP SA, DA
                new_icmp = '\x00' + icmp[1:] # change to echo reply type
                echo_reply = new_eth + new_ip + new_icmp
                self.send_packet(intf, echo_reply)
        else:
            self.handle_non_icmp_ip_packet_to_self(intf, eth, ip, proto)

    def handle_non_icmp_ip_packet_to_self(self, intf, eth, ip, proto):
        """Handles IP packets which are not ICMP packets by replying with a
        protocol unreachable ICMP message."""
        new_eth = eth[6:12] + eth[0:6] + eth[12:14] # reverse MAC SA, DA
        new_ip = ip[0:12] + ip[16:20] + ip[12:16]   # reverse IP SA, DA
        new_icmp = '\x03\x02\xfd\xfc' # dest unreach: proto unreach w/cksum
        proto_unreach = new_eth + new_ip + new_icmp
        self.send_packet(intf, proto_unreach)

    def handle_ip_packet_to_other(self, intf, eth, ip):
        """Called when a IP packet for someone else is received on intf.  eth
        holds the Ethernet frame bytes and ip holds the IP packet bytes.  This
        implementation simply drops the packet."""
        pass # ignore it

class VirtualNode(Node):
    """A node which a user can take control of (i.e., handle packets for)"""
    def __init__(self, name):
        Node.__init__(self, name)
        self.conn = None  # connection to the virtual host, if any

    def connect(self, conn):
        ret = ConnectionReturn(prev_client=self.conn)
        self.conn = conn
        return ret

    @staticmethod
    def get_type_str():
        return 'Virtual Node'

    def has_connection(self, conn):
        return self.conn == conn

    def disconnect(self, conn):
        if self.conn == conn:
            self.conn = None

    def handle_packet(self, intf, packet):
        """Forwards to the user responsible for handling packets for this virtual node"""
        if self.conn is not None:
            self.conn.send(VNSPacket(intf.name, packet))

class BlackHole(Node):
    """A node which discards all receives packets and sends no packets."""
    def __init__(self, name):
        Node.__init__(self, name)

    @staticmethod
    def get_type_str():
        return 'Black Hole'

    def handle_packet(self, incoming_intf, packet):
        """Discard all received packets."""
        pass

class Gateway(Node):
    """Shuffles packets between a simulated topology and the gateway router
    on the edge of the real network."""
    def __init__(self, name):
        Node.__init__(self, name)

    @staticmethod
    def get_type_str():
        return 'Gateway'

    @staticmethod
    def __is_private_address(ip):
        """Returns true if the IP is in 10/8, 172.16/12, or 192.168/16.  ip
        should be a string of four bytes."""
        if ip[0] == '\x10': # 10/8
            return False
        elif ip[0] == '\xac' and struct.unpack('> B', (ip[1])[0] & 0xF0)==16: # 172.16/12
            return False
        elif ip[0:2] == '\xc0\xa8': # 192.168/16
            return False
        else:
            return True

    def handle_packet(self, incoming_intf, packet):
        """Forwards an IP packet from the simulated topology to the network."""
        if len(packet) >= 34 and packet[12:14] == '\x08\x00':
            dst_ip = packet[30:34]
            if settings.MAY_FORWARD_TO_PRIVATE_IPS or not self.__is_private_address(dst_ip):
                logging.debug('ignoring IP packet to private address space: %s' % inet_ntoa(dst_ip))
                return

        logging.debug('TODO: forward packet out to the real network')

    def handle_packet_from_outside(self, packet):
        """Forwards the specified packet to the first hop in the topology."""
        if self.interfaces:
            if self.interfaces[0].link:
                self.interfaces[0].link.send_to_other(packet)

class Host(BasicNode):
    """A host in the network which replies to echo and ARP requests."""
    def __init__(self, name):
        BasicNode.__init__(self, name)

    @staticmethod
    def get_type_str():
        return 'Host'

class Hub(Node):
    """A hub"""
    def __init__(self, name):
        Node.__init__(self, name)

    @staticmethod
    def get_type_str():
        return 'Hub'

    def handle_packet(self, incoming_intf, packet):
        """Forward each received packet to every interface except the one it was received on"""
        for intf in self.interfaces:
            if intf.name != incoming_intf.name:
                self.send_packet(intf, packet)

class WebServer(BasicNode):
    """A host in the network which is serving a website on TCP port 80.  Like
    Host, it also replies to echo and ARP requests."""
    def __init__(self, name):
        BasicNode.__init__(self, name)

    @staticmethod
    def get_type_str():
        return 'Web Server'

    def handle_non_icmp_ip_packet_to_self(self, intf, eth, ip, proto):
        if proto == '\x06':
            self.handle_http_to_self(self, intf, eth, ip)

    def handle_http_to_self(self, intf, eth, ip):
        logging.debug('TODO: implement HTTP handling (proxy it to a real server)')

class VNSSimulator:
    """The VNS simulator.  It gives clients control of nodes in simulated
    topologies."""
    def __init__(self):
        self.topologies = {} # maps active topology ID to its Topology object
        self.border_addrs = {} # maps MAC/IP addrs of gateways to their Topology
        self.clients = {}    # maps active conn to the topology ID it is conn to
        self.server = create_vns_server(VNS_DEFAULT_PORT,
                                        self.handle_recv_msg,
                                        None,
                                        self.handle_client_disconnected)
        if settings.BORDER_DEV_NAME:
            self.__run_pcap(settings.BORDER_DEV_NAME)

    def __run_pcap(self, dev):
        """Start listening for packets coming in from the outside world."""
        MAX_LEN      = 1514    # max size of packet to capture
        PROMISCUOUS  = 1       # promiscuous mode?
        READ_TIMEOUT = 100     # in milliseconds
        PCAP_FILTER  = ''      # empty => get everything (or we could use a BPF filter)
        MAX_PKTS     = -1      # number of packets to capture; -1 => no limit

        # the method which will be called when a packet is captured
        def ph(_, data):
            # thread safety: call from the main twisted event loop
            reactor.callFromThread(self.handle_packet_from_outside, data)

        # start the packet capture
        p = open_live(dev, MAX_LEN, PROMISCUOUS, READ_TIMEOUT)
        p.setfilter(PCAP_FILTER)
        logging.info("Listening on %s: net=%s, mask=%s" % (dev, p.getnet(), p.getmask()))
        p.loop(MAX_PKTS, ph)

    @staticmethod
    def __get_dst_addr(packet):
        """Returns the address the packet is destined to.  This will be the
        Ethernet frame's destination MAC address except for ARP requests, in
        which case the destination IP from the ARP packet is used (since the
        destination MAC would be the broadcast MAC and we don't want to flood
        every simulation with every ARP request)."""
        if len(packet) < 14:
            return None # too small to even have an Ethernet header

        ether_type = packet[12:14]
        if ether_type == '\x08\x06': # ARP
            arp = packet[14:]
            if len(arp) < 28:
                return None # too small, ignore it

            arp_type = arp[6:8]
            if arp_type == '\x00\x01': # request
                return arp[24:28] # dst IP

        return packet[0:6] # dst MAC

    def handle_packet_from_outside(self, packet):
        """Forwards packet to the appropriate simulation, if any."""
        addr = VNSSimulator.__get_dst_addr(packet)
        if addr:
            topo = self.border_addrs.get(addr)
            if topo:
                topo.handle_packet_to_gateway(packet)

    def handle_recv_msg(self, conn, vns_msg):
        if vns_msg is not None:
            logging.debug('recv VNS msg: %s', vns_msg)
            if vns_msg.get_type() == VNSOpen.get_type():
                self.handle_open_msg(conn, vns_msg)
            elif vns_msg.get_type() == VNSClose.get_type():
                self.handle_close_msg(conn)
            elif vns_msg.get_type() == VNSPacket.get_type():
                self.handle_packet_msg(conn, vns_msg)

    def terminate_connection(self, conn, why, notify_client=True, log_it=True, lvl=logging.INFO):
        """Terminates the client connection conn.  This event will be logged
        unless log_it is False.  If notify_client is True, then the client will
        be sent a VNSClose message with an explanation."""
        # terminate the client
        if conn.connected:
            if notify_client:
                conn.send(VNSClose(why))
            conn.loseConnection()

        if log_it:
            logging.log(lvl, 'terminating client (%s): %s' % (conn, why))


        # cleanup client and topology info
        tid = self.clients.get(conn)
        if tid is not None:
            del self.clients[conn]
            topo = self.topologies[tid]
            topo.client_disconnected(conn)
            if not topo.is_active():
                for addr in topo.get_gateway_addrs():
                    del self.border_addrs[addr]
                del self.topologies[tid]

    def handle_open_msg(self, conn, open_msg):
        # get the topology the client is trying to connect to
        tid = open_msg.topo_id
        try:
            topo = self.topologies[tid]
        except KeyError:
            try:
                topo = Topology(tid)
                self.topologies[tid] = topo
                for addr in topo.get_gateway_addrs():
                    self.border_addrs[addr] = topo
            except db.Topology.DoesNotExist:
                self.terminate_connection(conn,
                                          'requested topology (%d) does not exist' % tid)
                return

        # try to connect the client to the requested node
        self.clients[conn] = tid
        requested_name = open_msg.vhost.replace('\x00', '')
        ret = topo.connect_client(conn, requested_name)
        if not ret.is_success():
            self.terminate_connection(conn, ret)
        if ret.prev_client:
            self.terminate_connection(ret.prev_client,
                                      'a new client (%s) has connected to the topology' % conn)

    def handle_client_disconnected(self, conn):
        self.terminate_connection(conn,
                                  'client disconnected (%s)' % conn,
                                  notify_client=False)

    def handle_close_msg(self, conn):
        self.terminate_connection(conn,
                                  'client sent VNSClose (%s)' % conn,
                                  notify_client=False)

    def handle_packet_msg(self, conn, pkt_msg):
        try:
            tid = self.clients[conn]
        except KeyError:
            msg = 'client %s sent VNSPacket message while not connected to any topology' % conn
            self.terminate_connection(conn, msg, lvl=logging.WARN)
            return

        try:
            topo = self.topologies[tid]
        except KeyError:
            msg = 'client %s sent VNSPacket message but its topology (%d) is not active' % (conn, tid)
            self.terminate_connection(conn, msg, lvl=logging.WARN)
            return

        try:
            ret = topo.handle_packet_from_client(conn, pkt_msg)
        except KeyError:
            msg = 'client %s sent VNSPacket message but its topology (%d) does not think it is connected to any node' % (conn, tid)
            self.terminate_connection(conn, msg, lvl=logging.WARN)

        if ret is not True: # bad interface name was given
            self.terminate_connection(conn, ret)

def main():
    VNSSimulator()
    reactor.run()

if __name__ == "__main__":
    main()
