import hashlib
import logging
import random
import socket
from socket import inet_aton, inet_ntoa
import struct

from settings import MAY_FORWARD_TO_PRIVATE_IPS
from LoggingHelper import log_exception, addrstr, hexstr, pktstr
import ProtocolHelper
from VNSProtocol import VNSPacket, VNSInterface, VNSHardwareInfo
import web.vns.models as db

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

        # determine who may use this topology
        tus = db.TopologyUser.objects.filter(topology=t)
        if len(tus) > 0:
            self.permitted_source_prefixes = [tu.subnet_str() for tu in tus]
        else:
            self.permitted_source_prefixes = ['0.0.0.0/32'] # unrestricted

        # Salt for MAC address generation: ensures a topology which reuses
        # shared IPs still gets unique MAC addresses so that ARP requests really
        # intended for other topologies don't end up on every copy of the topo.
        self.mac_salt = ''.join([hashlib.md5(psp).digest() for psp in self.permitted_source_prefixes])

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
            # TODO: we're hitting the DB a lot here; could optimize a bit
            ipa = db.IPAssignment.objects.get(topology=t, port=dp)
            try:
                mac = db.MACAssignment.objects.get(topology=t, port=dp).get_mac()
            except db.MACAssignment.DoesNotExist:
                mac = ipa.get_mac(self.mac_salt)
            intf = sn.add_interface(dp.name, mac, ipa.get_ip(), ipa.get_mask())
            interfaces_db_to_sim[dp] = intf

        # read in this topology's links
        links = db.Link.objects.filter(port1__node__template=t.template)
        for db_link in links:
            intf1 = interfaces_db_to_sim[db_link.port1]
            intf2 = interfaces_db_to_sim[db_link.port2]
            Link(intf1, intf2, db_link.lossiness)

        logging.info('Topology instantiated:\n%s' % self.str_all(include_clients=False))

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
                    fmt = 'client (%s) has connected to node %s on topology %d'
                    logging.info(fmt % (client_conn, n, self.id))
                return ret
        return ConnectionReturn('there is no node named %s' % requested_name)

    def client_disconnected(self, client_conn):
        n = self.clients.pop(client_conn)
        n.disconnect(client_conn)

    def has_gateway(self):
        """Returns True if this topology has a gateway."""
        return self.gateway is not None

    def get_my_ip_addrs(self):
        """Returns a list of IP addresses (as byte-strings) which belong to
        nodes (except the gateway) in this topology."""
        addrs = []
        for node in self.nodes:
            if node is not self.gateway:
                for intf in node.interfaces:
                    addrs.append(intf.ip)
        return addrs

    def get_my_mac_addrs(self):
        """Returns a list of Ethernet addresses (as byte-strings) which belong
        to nodes (except the gateway) in this topology."""
        addrs = []
        for node in self.nodes:
            if node is not self.gateway:
                for intf in node.interfaces:
                    addrs.append(intf.mac)
        return addrs

    def get_id(self):
        """Returns this topology's unique ID number."""
        return self.id

    def get_source_filters(self):
        """Returns a list of IP prefixes which should be routed to this
        topology.  This list will always contain at least one prefix."""
        return self.permitted_source_prefixes

    def handle_packet_from_client(self, conn, pkt_msg):
        """Sends the specified message out the specified port on the node
        controlled by conn.  If conn does not control a node, then a KeyError is
        raised.  If conn's node does not have an interface with the specified
        name then an error message is returned.  Otherwise, True is returned."""
        departure_intf_name = pkt_msg.intf_name.replace('\x00', '')
        n = self.clients[conn]
        for intf in n.interfaces:
            if intf.name == departure_intf_name:
                logging.debug('%s: client sending packet from %s out %s: %s' %
                              (self, n.name, intf.name, pktstr(pkt_msg.ethernet_frame)))
                n.send_packet(intf, pkt_msg.ethernet_frame)
                return True

        # failed to find the specified interface
        fmt = 'bad packet request: invalid interface: %s'
        return fmt % (n.name, departure_intf_name)

    def handle_incoming_packet(self, packet, rewrite_dst_mac):
        """Forwards packet to the node connected to the gateway.  If
        rewrite_dst_mac is True then the destination mac is set to that of the
        first simulated node attached to the gateway."""
        if len(self.gateway.interfaces) > 0:
            intf = self.gateway.interfaces[0]
            if intf.link:
                if rewrite_dst_mac:
                    new_dst_mac = intf.link.get_other(intf).mac
                    intf.link.send_to_other(intf, new_dst_mac + packet[6:])
                else:
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
        topo = self
        if dn.type == db.Node.VIRTUAL_NODE_ID:
            return VirtualNode(topo, dn.name)
        elif dn.type == db.Node.BLACK_HOLE_ID:
            return BlackHole(topo, dn.name)
        elif dn.type == db.Node.HUB_ID:
            return Hub(topo, dn.name)
        elif dn.type == db.Node.WEB_SERVER_ID:
            hostname = dn.webserver.web_server_addr.get_ascii_hostname()
            return WebServer(topo, dn.name, hostname)
        elif dn.type == db.Node.GATEWAY_ID:
            if self.gateway is not None:
                err = 'only one gateway per topology is allowed'
            else:
                self.gateway = Gateway(topo, dn.name, raw_socket)
                return self.gateway
        else:
            err = 'unknown node type: %d' % dn.type
        logging.critical(err)
        raise db.Topology.DoesNotExist(err)

    def __str__(self):
        return 'Topology %d' % self.id

    def str_all(self, include_clients=True):
        """Returns a complete string representation of this topology."""
        str_hdr = self.__str__()
        if not include_clients:
            str_clients = ''
        elif self.clients:
            str_clients = 'Clients: %s\n  ' % ','.join([str(c) for c in self.clients])
        else:
            str_clients = 'Clients: none connected\n  '
        str_psp = 'Source IP Prefixes: %s' % ','.join(self.permitted_source_prefixes)
        str_nodes = 'Nodes:\n    ' + '\n    '.join([n.str_all() for n in self.nodes])
        return '%s:\n  %s%s\n  %s' % (str_hdr, str_clients, str_psp, str_nodes)

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

    def __str__(self):
        return '%s: %s:%s <--> %s:%s' % (self.intf1.owner.name, self.intf1.name,
                                         self.intf2.owner.name, self.intf2.name)

    def str_half(self, intf):
        """Returns the name and port of the other side of the link."""
        other_intf = self.get_other(intf)
        return '-> %s:%s' % (other_intf.owner.name, other_intf.name)

class Node:
    """A node in a topology"""
    def __init__(self, topo, name):
        self.topo = topo
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

    def __str__(self):
        return '%s (%s)' % (self.name, self.get_type_str())

    @staticmethod
    def __get_intf_str(intf):
        str_link = intf.link.str_half(intf) if intf.link else ''
        return '%s={%s,%s}%s' % (intf.name, addrstr(intf.ip), addrstr(intf.mac), str_link)

    def di(self):
        """Returns a short string with topology info and node name."""
        return '%s %s' % (self.topo, self.name)

    def str_all(self):
        """Returns a complete string representation of this node."""
        str_hdr = self.__str__()
        str_intfs = ','.join([Node.__get_intf_str(i) for i in self.interfaces])
        return '%s: %s' % (str_hdr, str_intfs)

class BasicNode(Node):
    """A basic node which replies to ARP and ICMP Echo requests.  Further
    handling of IP packets is delegated to subclasses."""
    def __init__(self, topo, name):
        Node.__init__(self, topo, name)

    @staticmethod
    def get_type_str():
        return 'Undefined Basic Node'

    def handle_packet(self, intf, packet):
        """Responses to ARP requests (as appropriate) and forwards IP packets."""
        if len(packet) < 14:
            logging.debug('%s ignoring packet which is too small: %dB' % (self.di(), len(packet)))
            return

        logging.debug('%s handling packet: %s' % (self.di(), pktstr(packet)))
        pkt = ProtocolHelper.Packet(packet)
        if pkt.is_valid_ipv4():
            self.handle_ipv4_packet(intf, pkt)
        elif pkt.is_valid_arp():
            self.handle_arp_packet(intf, pkt)

    def handle_arp_packet(self, intf, pkt):
        """Respond to arp if it is a request for the mac address of intf's IP."""
        if pkt.arp_type != '\x00\x01': # only handle ARP REQUESTs
            logging.debug('%s ignoring ARP which is not a request' % self.di())
            return

        # is the ARP request asking about THIS interface on broadcast dha?
        intf_ip_packed = struct.pack('> I', intf.ip)
        if pkt.dpa==intf_ip_packed and pkt.dha=='\xFF\xFF\xFF\xFF\xFF\xFF':
            # send it back to the requester (reverse src/dst, copy in our mac addr)
            reply_eth = pkt.get_reversed_eth()
            reply_arp = pkt.arp[0:8] + intf.mac + intf_ip_packed + pkt.sha + pkt.spa
            reply = reply_eth + reply_arp
            logging.debug('%s replying to ARP request: %s' % (self.di(), reply))
            self.send_packet(intf, reply)

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
                logging.debug('%s replying to echo request: %s' % (self.di(), echo_reply))
                self.send_packet(intf, echo_reply)
            else:
                logging.debug('%s ignoring ICMP which is not an echo request' % self.di())
        else:
            self.handle_non_icmp_ip_packet_to_self(intf, pkt)

    def handle_non_icmp_ip_packet_to_self(self, intf, pkt):
        """Handles IP packets which are not ICMP packets by replying with a
        protocol unreachable ICMP message."""
        new_eth = pkt.get_reversed_eth()
        new_ip = pkt.get_reversed_ip(new_ttl=64)
        new_icmp = '\x03\x02\xfd\xfc' # dest unreach: proto unreach w/cksum
        proto_unreach = new_eth + new_ip + new_icmp
        logging.debug('%s sending protocol unreachable in response to non-ICMP IP packet: %s' % (self.di(), proto_unreach))
        self.send_packet(intf, proto_unreach)

    def handle_ipv4_packet_to_other(self, intf, pkt):
        """Called when a IP packet for someone else is received on intf.  eth
        holds the Ethernet frame bytes and ip holds the IP packet bytes.  This
        implementation simply drops the packet."""
        logging.debug('%s ignoring IP packet to someone else' % self.di())

class VirtualNode(Node):
    """A node which a user can take control of (i.e., handle packets for)"""
    def __init__(self, topo, name):
        Node.__init__(self, topo, name)
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

    def handle_packet(self, incoming_intf, packet):
        """Forwards to the user responsible for handling packets for this virtual node"""
        if self.conn is not None:
            logging.debug('%s got packet on %s - forwarding to VNS client: %s' %
                          (self.di(), incoming_intf.name, pktstr(packet)))
            self.conn.send(VNSPacket(incoming_intf.name, packet))

    def __str__(self):
        return Node.__str__(self) + ' client=%s' % self.conn

class BlackHole(Node):
    """A node which discards all receives packets and sends no packets."""
    def __init__(self, topo, name):
        Node.__init__(self, topo, name)

    @staticmethod
    def get_type_str():
        return 'Black Hole'

    def handle_packet(self, incoming_intf, packet):
        """Discard all received packets."""
        logging.debug('%s got packet on %s - black-holing it: %s' %
                      (self.di(), incoming_intf.name, pktstr(packet)))

class Gateway(Node):
    """Shuffles packets between a simulated topology and the gateway router
    on the edge of the real network."""
    def __init__(self, topo, name, raw_socket):
        Node.__init__(self, topo, name)
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
            if MAY_FORWARD_TO_PRIVATE_IPS or not self.__is_private_address(dst_ip):
                logging.debug('%s ignoring IP packet to private address space: %s' % (self.di(), inet_ntoa(dst_ip)))
                return

        # forward packet out to the real network
        if self.raw_socket:
            try:
                logging.debug('%s sending packet out to the real world: %s' % (self.di(), pktstr(packet)))
                self.raw_socket.send(packet)
            except socket.error:
                # this is recoverable - the network may come back up
                log_exception(logging.WARN,
                              'unable to forward packet to the real network')

    def handle_packet_from_outside(self, packet):
        """Forwards the specified packet to the first hop in the topology."""
        if self.interfaces:
            if self.interfaces[0].link:
                logging.debug('%s got packet from outside - forwarding it: %s' % (self.di(), pktstr(packet)))
                self.interfaces[0].link.send_to_other(packet)

class Host(BasicNode):
    """A host in the network which replies to echo and ARP requests."""
    def __init__(self, topo, name):
        BasicNode.__init__(self, topo, name)

    @staticmethod
    def get_type_str():
        return 'Host'

class Hub(Node):
    """A hub"""
    def __init__(self, topo, name):
        Node.__init__(self, topo, name)

    @staticmethod
    def get_type_str():
        return 'Hub'

    def handle_packet(self, incoming_intf, packet):
        """Forward each received packet to every interface except the one it was received on"""
        logging.debug('%s got packet on %s - forwarding it out all other ports: %s' %
                      (self.di(), incoming_intf.name, pktstr(packet)))
        for intf in self.interfaces:
            if intf.name != incoming_intf.name:
                self.send_packet(intf, packet)

class WebServer(BasicNode):
    """A host in the network which is serving a website (specified by the
    web_server_to_proxy_hostname parameter) on TCP port 80.  Like
    Host, it also replies to echo and ARP requests.  It serves the specified
    website by acting as a proxy for that website."""
    def __init__(self, topo, name, web_server_to_proxy_hostname):
        BasicNode.__init__(self, topo, name)
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
            self.web_server_to_proxy_ip = inet_aton(str_ip)
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
            logging.debug('%s forwarding new HTTP request: client=%s me=%s' %
                          (self.di(), str(client_info), hexstr(my_port)))
        else:
            logging.debug('%s forwarding ongoing HTTP request: client=%s me=%s' %
                          (self.di(), str(client_info), hexstr(my_port)))

        # rewrite and forward the request to the web server we're proxying
        new_dst = self.web_server_to_proxy_ip
        new_packet = pkt.modify_tcp_packet(new_dst, pkt.tcp_dst_port,
                                           my_port, reverse_eth=True)
        intf.link.send_to_other(new_packet)

        self.__check_for_teardown(pkt, client_info, my_port)

    def handle_http_reply(self, intf, pkt):
        """Forward the received packet from the web server to the HTTP client."""
        if pkt.ip_dst != self.web_server_to_proxy_ip:
            logging.debug('%s ignoring HTTP reply from unexpected source %s' % (self.di(), addrstr(pkt.ip_dst)))
            return # ignore HTTP replies unless they're from our web server

        client_info = self.conns.get(pkt.tcp_dst_port)
        if client_info is None:
            logging.debug('%s ignoring unexpected HTTP reply to my port %s' % (self.di(), hexstr(pkt.tcp_dst_port)))
            return # ignore unexpected replies
        logging.debug('%s forwarding HTTP reply to client=%s from me=%s' % (self.di(), str(client_info), hexstr(pkt.tcp_dst_port)))

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
            logging.debug('%s HTTP connection state removed (RST or final FIN)' % self.di())

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

    def __str__(self):
        ps = ' proxying={%s->%s}' % (self.web_server_to_proxy_hostname, addrstr(self.web_server_to_proxy_ip))
        return BasicNode.__str__(self) + ps
