"""The VNS simulator."""
import ProtocolHelper

import errno
import logging.config
import random
import socket
from socket import inet_ntoa
import struct
import sys
import traceback

from pcapy import open_live, PcapError
from twisted.internet import reactor

import settings
import web.vns.models as db
from ProtocolHelper import Packet
from VNSProtocol import VNS_DEFAULT_PORT, create_vns_server
from VNSProtocol import VNSOpen, VNSClose, VNSPacket, VNSInterface, VNSHardwareInfo

logging.config.fileConfig('logging.conf')

def log_exception(lvl, msg):
    """Like logging.exception(msg) except you may choose what level to log to."""
    logging.log(lvl, msg + '\n' + traceback.format_exc()[:-1])

class ConnectionReturn():
    def __init__(self, fail_reason=None, prev_client=None):
        self.fail_reason = fail_reason
        self.prev_client = prev_client

    def is_success(self):
        return self.fail_reason is None

class Topology():
    """A topology to simulate."""
    def __init__(self, tid, raw_socket):
        """Reads topology with the specified id from the database.  A
        DoesNotExist exception (Topology or IPAssignment) is raised if this fails."""
        # maps clients connected to this topology to the node they are connected to
        self.clients = {}

        t = db.Topology.objects.get(pk=tid)
        self.id = tid

        # read in this topology's nodes
        db_nodes = db.Node.objects.filter(template=t.template)
        self.gateway = None
        self.nodes = [self.__make_node(dn, raw_socket) for dn in db_nodes]

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

    def __make_node(self, dn, raw_socket):
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
            return WebServer(dn.name, dn.webserver.web_server_addr.hostname)
        elif dn.type == db.Node.GATEWAY_ID:
            if self.gateway is not None:
                err = 'only one gateway per topology is allowed'
            else:
                self.gateway = Gateway(dn.name, raw_socket)
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
        should be a network byte-order byte-string."""
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

        pkt = Packet(packet)
        if pkt.is_valid_ipv4():
            self.handle_ipv4_packet(intf, pkt)
        elif pkt.is_valid_arp():
            self.handle_arp_packet(intf, pkt)

    def handle_arp_packet(self, intf, pkt):
        """Respond to arp if it is a request for the mac address of intf's IP."""
        if pkt.arp_type != '\x00\x01': # only handle ARP REQUESTs
            return

        # is the ARP request asking about THIS interface on broadcast dha?
        intf_ip_packed = struct.pack('> I', intf.ip)
        if pkt.dpa==intf_ip_packed and pkt.dha=='\xFF\xFF\xFF\xFF\xFF\xFF':
            # send it back to the requester (reverse src/dst, copy in our mac addr)
            reply_eth = pkt.get_reversed_eth()
            reply_arp = pkt.arp[0:8] + intf.mac + intf_ip_packed + pkt.sha + pkt.spa
            self.send_packet(intf, reply_eth + reply_arp)

    def handle_ipv4_packet(self, intf, pkt):
        """Replies to an ICMP echo request to this node.  Other handling is
        delegated to subclasses."""
        if self.has_ip(pkt.ip_dst):
            self.handle_ipv4_packet_to_self(intf, pkt)
        else:
            self.handle_ipv4_packet_to_other(intf, pkt)

    def handle_ipv4_packet_to_self(self, intf, pkt):
        """Called when a IP packet for on of our interfaces is received on intf.
        eth holds the Ethernet frame bytes and ip holds the IP packet bytes.
        This implementation replies with an echo reply or protocol unreachable
        as appropriate."""
        if pkt.ip_proto == '\x01':
            icmp = pkt.ip_payload
            if icmp[0] == '\x08': # echo request
                new_eth = pkt.get_reversed_eth()
                new_ip = pkt.get_reversed_ip(new_ttl=64)
                new_icmp = '\x00' + icmp[1:] # change to echo reply type
                echo_reply = new_eth + new_ip + new_icmp
                self.send_packet(intf, echo_reply)
        else:
            self.handle_non_icmp_ip_packet_to_self(intf, pkt)

    def handle_non_icmp_ip_packet_to_self(self, intf, pkt):
        """Handles IP packets which are not ICMP packets by replying with a
        protocol unreachable ICMP message."""
        new_eth = pkt.get_reversed_eth()
        new_ip = pkt.get_reversed_ip(new_ttl=64)
        new_icmp = '\x03\x02\xfd\xfc' # dest unreach: proto unreach w/cksum
        proto_unreach = new_eth + new_ip + new_icmp
        self.send_packet(intf, proto_unreach)

    def handle_ipv4_packet_to_other(self, intf, pkt):
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
    def __init__(self, name, raw_socket):
        Node.__init__(self, name)
        self.raw_socket = raw_socket

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

        # forward packet out to the real network
        if self.raw_socket:
            try:
                self.raw_socket.send(packet)
            except socket.error:
                # this is recoverable - the network may come back up
                log_exception(logging.WARN,
                              'unable to forward packet to the real network')

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
    """A host in the network which is serving a website (specified by the
    web_server_to_proxy_hostname parameter) on TCP port 80.  Like
    Host, it also replies to echo and ARP requests.  It serves the specified
    website by acting as a proxy for that website."""
    def __init__(self, name, web_server_to_proxy_hostname):
        BasicNode.__init__(self, name)
        self.web_server_to_proxy_hostname = web_server_to_proxy_hostname
        self.__init_web_server_ip()

        # Each request is from a unique socket (TCP port and IP pair).  It is
        # then forwarded from a different local TCP port to the web server this
        # node is proxying.  The request to local port mapping as well as the
        # reverse mapping is stored in conns.  Keys and values are all raw
        # byte-strings in network byte order.
        self.conns = {}  # (requester IP, TCP port) <=> local TCP port
        self.fins = {} # keys = conns key which has sent a FIN
        self.next_tcp_port = 10000  # next TCP port to forward from

    def __init_web_server_ip(self):
        """Resolves the target web server hostname to an IP address."""
        try:
            str_ip = socket.gethostbyname(self.web_server_to_proxy_hostname)
            self.web_server_to_proxy_ip = socket.inet_aton(str_ip)
        except socket.gaierror:
            self.web_server_to_proxy_ip = None
            log_exception(logging.WARN,
                          'unable to resolve web server hostname: ' + self.web_server_to_proxy_hostname)

    @staticmethod
    def get_type_str():
        return 'Web Server'

    def __has_web_server_ip(self):
        """Returns True if the hostname was successfully resolved to an IP."""
        return self.web_server_to_proxy_ip is None

    def handle_non_icmp_ip_packet_to_self(self, intf, pkt):
        """If pkt is part of an HTTP exchange on HTTP_PORT, then the packet is
        forwarded as appropriate (this node acts as a proxy server)  Otherwise,
        the default superclass implementation is called."""
        if pkt.is_valid_tcp() and self.__has_web_server_ip():
            if pkt.tcp_dst_port == ProtocolHelper.HTTP_PORT:
                self.handle_http_request(self, intf, pkt)
                return
            elif pkt.tcp_dst_port == ProtocolHelper.HTTP_PORT:
                self.handle_http_reply(self, intf, pkt)
                return

        BasicNode.handle_non_icmp_ip_packet_to_self(self, intf, pkt)

    def handle_http_request(self, intf, pkt):
        """Forward the received packet from an HTTP client to the web server."""
        # see if we are already working with this connection
        client_info = (pkt.ip_src, pkt.tcp_src_port)
        my_port = self.conns.get(client_info)
        if my_port is None:
            # new connection: allocate a port for it
            my_port = struct.pack('> H', self.next_tcp_port)
            self.next_tcp_port += 1
            if self.next_tcp_port > 65535:
                self.next_tcp_port = 10000
            self.conns[client_info] = my_port
            self.conns[my_port] = client_info

        # rewrite and forward the request to the web server we're proxying
        new_dst = self.web_server_to_proxy_ip
        new_packet = pkt.modify_tcp_packet(new_dst, pkt.tcp_dst_port,
                                           my_port, reverse_eth=True)
        intf.link.send_to_other(new_packet)

        self.__check_for_teardown(pkt, client_info, my_port)

    def handle_http_reply(self, intf, pkt):
        """Forward the received packet from the web server to the HTTP client."""
        if pkt.ip_dst != self.web_server_to_proxy_ip:
            return # ignore HTTP replies unless they're from our web server

        client_info = self.conns.get(pkt.tcp_dst_port)
        if client_info is None:
            return # ignore unexpected replies

        # rewrite and forward the reply back to the client its associated with
        (client_ip, client_tcp_port) = client_info
        new_packet = pkt.modify_tcp_packet(client_ip, client_tcp_port,
                                           pkt.tcp_src_port, reverse_eth=True)
        intf.link.send_to_other(new_packet)

        self.__check_for_teardown(pkt, pkt.tcp_dst_port, client_info)

    def __check_for_teardown(self, pkt, side_from, other_side):
        """Checks to see if a TCP RST or the final FIN has been received from
        side_from and handles them appropriately if so."""
        if pkt.is_tcp_rst() or self.__is_full_close(pkt, side_from, other_side):
            del self.conns[side_from]
            del self.conns[other_side]
            self.fins.pop(other_side, None)

    def __is_full_close(self, pkt, side_from, other_side):
        """Checks to see if pkt from side_from is a FIN.  Returns True if
        other_side has already sent a FIN.  Otherwise returns False."""
        if not pkt.is_tcp_fin():
            return False
        elif self.fins.has_key(other_side):
            return True
        else:
            self.fins[side_from] = True # cleaned up by __check_for_teardown
            return False

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
            self.__start_raw_socket(settings.BORDER_DEV_NAME)
            # run pcap in another thread (it will run forever)
            reactor.callInThread(self.__run_pcap, settings.BORDER_DEV_NAME)
        else:
            self.raw_socket = None

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
        try:
            p = open_live(dev, MAX_LEN, PROMISCUOUS, READ_TIMEOUT)
        except PcapError:
            log_exception(logging.CRITICAL, 'failed to start pcap')
            sys.exit(-1)

        p.setfilter(PCAP_FILTER)
        logging.info("Listening on %s: net=%s, mask=%s" % (dev, p.getnet(), p.getmask()))
        p.loop(MAX_PKTS, ph)

    def __start_raw_socket(self, dev):
        """Starts a socket for sending raw Ethernet frames."""
        try:
            self.raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
            self.raw_socket.bind((dev, 0x9999))
        except socket.error as e:
            if e.errno == errno.EPERM:
                extra = ' (did you forget to run me with root?)'
            else:
                extra = ''
            log_exception(logging.CRITICAL, 'failed to open raw socket' + extra)
            sys.exit(-1)

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
                topo = Topology(tid, self.raw_socket)
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
