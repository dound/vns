import hashlib
import logging
import Queue
import random
import socket
from socket import inet_aton, inet_ntoa
import struct
import time

from settings import ARP_CACHE_TIMEOUT, MAY_FORWARD_TO_PRIVATE_IPS, WEB_SERVER_ROOT_WWW
from DRRQueue import DRRQueue
from HTTPServer import HTTPServer
from LoggingHelper import log_exception, addrstr, pktstr
import ProtocolHelper
from ProtocolHelper import is_http_port, Packet
from TCPStack import TCPServer
from VNSProtocol import VNSPacket, VNSInterface, VNSHardwareInfo
import web.vnswww.models as db

MAX_JOBS_PER_TOPO = 25

class ConnectionReturn():
    def __init__(self, fail_reason=None, prev_client=None):
        self.fail_reason = fail_reason
        self.prev_client = prev_client

    def is_success(self):
        return self.fail_reason is None

class TopologyCreationException(Exception):
    def __init__(self, problem):
        self.problem = problem

    def __str__(self):
        return self.problem

class Topology():
    """A topology to simulate."""
    def __init__(self, tid, raw_socket, client_ip, user, start_stats=True):
        """Reads topology with the specified id from the database.  A
        DoesNotExist exception (Topology, IPAssignment, or IPBlockAllocation) is
        raised if this fails."""
        self.raw_socket = raw_socket

        # stores jobs which need to be done for this topology
        self.job_queue = DRRQueue(MAX_JOBS_PER_TOPO)

        # maps clients connected to this topology to the node they are connected to
        self.clients = {}

        # a list of packets destined to the first hop pending an ARP translation
        self.pending_incoming_packets = []

        # last time an ARP translation was completed / requested
        self.last_arp_translation = 0
        self.last_arp_translation_request = 0

        # current ARP translation
        self.arp_translation = None

        t = db.Topology.objects.get(pk=tid)
        if not t.enabled:
            raise TopologyCreationException('topology %d is disabled' % tid)
        self.id = tid
        self.temporary = t.temporary

        # determine what IP block is allocated to this topology
        ipba = db.IPBlockAllocation.objects.get(topology=t)
        self.ip_block = (struct.unpack('>I',inet_aton(ipba.start_addr))[0], ipba.mask)

        # determine who may connect to nodes in this topology
        if t.public:
            # anyone may use it
            self.permitted_clients = None
        else:
            tufs = db.TopologyUserFilter.objects.filter(topology=t)
            self.permitted_clients = [tuf.user for tuf in tufs]
            self.permitted_clients.append(t.owner)

        # determine what IPs may interact with this topology
        tus = db.TopologySourceIPFilter.objects.filter(topology=t)
        if len(tus) > 0:
            self.permitted_source_prefixes = [tu.subnet_mask_str() for tu in tus]
        else:
            self.permitted_source_prefixes = ['0.0.0.0/0'] # unrestricted

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
            mac, ip, mask = self.__get_addr_assignments_for_node(t, sn, dp)
            intf = sn.add_interface(dp.name, mac, ip, mask)
            interfaces_db_to_sim[dp] = intf

        # read in this topology's links
        links = db.Link.objects.filter(port1__node__template=t.template)
        for db_link in links:
            intf1 = interfaces_db_to_sim[db_link.port1]
            intf2 = interfaces_db_to_sim[db_link.port2]
            Link(intf1, intf2, db_link.lossiness)

        # get the interface to the first hop (if a first hop exists)
        self.gw_intf_to_first_hop = None
        if len(self.gateway.interfaces) > 0:
            intf = self.gateway.interfaces[0]
            if intf.link:
                self.gw_intf_to_first_hop = intf

        if start_stats:
            self.stats = db.UsageStats()
            self.stats.init(t, client_ip, user)
            self.stats.save()
            logging.info('Topology instantiated:\n%s' % self.str_all(include_clients=False))

    def __get_addr_assignments_for_node(self, t, sn, dp):
        if sn.get_type_str() == 'Gateway':
            # TODO: get the appropriate simulator object (assuming there's only one for now)
            sim = db.Simulator.objects.all()[0]
            ip = inet_aton(sim.gatewayIP)
            mac = ''.join([struct.pack('>B', int(b, 16)) for b in sim.gatewayMAC.split(':')])
            return (mac, ip, '\x00\x00\x00\x00')
        else:
            ipa = db.IPAssignment.objects.get(topology=t, port=dp)
            try:
                mac = db.MACAssignment.objects.get(topology=t, port=dp).get_mac()
            except db.MACAssignment.DoesNotExist:
                mac = ipa.get_mac(self.mac_salt)
            return (mac, ipa.get_ip(), ipa.get_mask())

    def connect_client(self, client_conn, client_user, requested_name):
        """Called when a user tries to connect to a node in this topology.
        Returns True if the requested node exists and the client was able to
        connect to it.  Otherwise it returns an error message."""
        if self.permitted_clients is not None: # otherwise anyone can use it
            if client_user not in self.permitted_clients:
                return ConnectionReturn('%s is not authorized to use this topology' % client_user)

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
        n = self.clients.pop(client_conn, None)
        if n:
            n.disconnect(client_conn)

    def get_clients(self):
        """Returns a list of clients connected to this Topology."""
        return self.clients.keys()

    def has_gateway(self):
        """Returns True if this topology has a gateway."""
        return self.gateway is not None

    def is_temporary(self):
        """Returns True if this topology is only temporary."""
        return self.temporary

    def get_my_ip_addrs(self):
        """Returns a list of IP addresses (as byte-strings) which belong to
        nodes (except the gateway) in this topology."""
        addrs = []
        for node in self.nodes:
            if node is not self.gateway:
                for intf in node.interfaces:
                    addrs.append(intf.ip)
        return addrs

    def get_my_ip_block(self):
        """Returns a 2-tuple containing the subnet and associated mask which
        contains all IPs assigned to this topology.  The subnet is expressed as
        a 4B NBO integer."""
        return self.ip_block

    def get_all_ip_addrs_in_my_ip_block(self):
        """Returns a list of NBO byte-strings representing the IPs allocated to this topology."""
        dst_block_start_ip, dst_block_mask = self.get_my_ip_block()
        return [struct.pack('>I',dst_block_start_ip+i) for i in xrange(2**(32-dst_block_mask))]

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

    def get_stats(self):
        """Returns the UsageStats object maintained by this Topology instance."""
        return self.stats

    def handle_packet_from_client(self, conn, pkt_msg):
        """Sends the specified message out the specified port on the node
        controlled by conn.  If conn does not control a node, then a KeyError is
        raised.  If conn's node does not have an interface with the specified
        name then an error message is returned.  Otherwise, True is returned."""
        departure_intf_name = pkt_msg.intf_name
        n = self.clients[conn]
        for intf in n.interfaces:
            if intf.name == departure_intf_name:
                logging.debug('%s: client sending packet from %s out %s: %s' %
                              (self, n.name, intf.name, pktstr(pkt_msg.ethernet_frame)))
                self.stats.note_pkt_from_client(len(pkt_msg.ethernet_frame))
                n.send_packet(intf, pkt_msg.ethernet_frame)
                return True

        # failed to find the specified interface
        fmt = 'bad packet request: invalid interface: %s'
        return fmt % (n.name, departure_intf_name)

    def create_job_for_incoming_packet(self, packet, rewrite_dst_mac):
        """Enqueues a job for handling this packet with handle_incoming_packet()."""
        try:
            self.job_queue.put_nowait(lambda : self.handle_incoming_packet(packet, rewrite_dst_mac))
        except Queue.Full:
            logging.debug("Queue full for topology %s, dropping incoming packet: %s" % (str(self), pktstr(packet)))

    def handle_incoming_packet(self, packet, rewrite_dst_mac):
        """Forwards packet to the node connected to the gateway.  If
        rewrite_dst_mac is True then the destination mac is set to that of the
        first simulated node attached to the gateway."""
        gw_intf = self.gw_intf_to_first_hop
        if gw_intf:
            self.stats.note_pkt_to_topo(len(packet))
            if rewrite_dst_mac:
                if self.is_arp_cache_valid():
                    new_dst_mac = self.arp_translation
                    gw_intf.link.send_to_other(gw_intf, new_dst_mac + packet[6:])
                else:
                    self.need_arp_translation_for_pkt(packet)
            else:
                gw_intf.link.send_to_other(gw_intf, packet)

    def need_arp_translation_for_pkt(self, ethernet_frame):
        """Delays forwarding a packet to the node connected to the gateway until
        it replies to an ARP request."""
        if len(self.pending_incoming_packets) < 10:
            self.pending_incoming_packets.append(ethernet_frame)
        # otherwise: drop new packets if the psuedo-queue is full

        if not self.is_ok_to_send_arp_request():
            return # we already sent an ARP request recently, so be patient!
        else:
            self.last_arp_translation_request = time.time()

        gw_intf = self.gw_intf_to_first_hop
        dst_mac = '\xFF\xFF\xFF\xFF\xFF\xFF' # broadcast
        src_mac = gw_intf.mac
        eth_type = '\x08\x06'
        eth_hdr = dst_mac + src_mac + eth_type
        dst_ip = gw_intf.link.get_other(gw_intf).ip
        src_ip = gw_intf.ip
        # hdr: HW=Eth, Proto=IP, HWLen=6, ProtoLen=4, Type=Request
        arp_hdr = '\x00\x01\x08\x00\x06\x04\x00\x01'
        arp_request = eth_hdr + arp_hdr + src_mac + src_ip + dst_mac + dst_ip
        gw_intf.link.send_to_other(gw_intf, arp_request)

    def update_arp_translation(self, addr):
        """Updates the ARP translation to the first hop and sends out any
        pending packets."""
        self.arp_translation = addr
        self.last_arp_translation = time.time()
        gw_intf = self.gw_intf_to_first_hop
        if gw_intf:
            for packet in self.pending_incoming_packets:
                new_pkt = self.arp_translation + packet[6:]
                gw_intf.link.send_to_other(gw_intf, new_pkt)
            self.pending_incoming_packets = [] # clear the list

    def get_node_and_intf_with_link(self, node_name, intf_name):
        """Returns a 2-tuple containg the named node and interface if they exist
        and there is a link from it.  Otherwise a string describing the problem
        is returned."""
        for n in self.nodes:
            if n.name == node_name:
                for intf in n.interfaces:
                    if intf.name == intf_name:
                        if intf.link:
                            return (n, intf)
                        else:
                            return '%s:%s has no link attached to it' % (node_name, intf_name)
                return 'there is no interface %s on node %s' % (intf_name, n.str_all())
        return 'there is no node named %s' % node_name

    def send_packet_from_node(self, node_name, intf_name, ethernet_frame):
        """Sends a packet from the request node's specified interface.  True is
        returned on success; otherwise a string describing the error is returned."""
        ret = self.get_node_and_intf_with_link(node_name, intf_name)
        if isinstance(ret, basestring):
            return ret
        else:
            _, intf = ret
            self.stats.note_pkt_to_topo(len(ethernet_frame))
            intf.link.send_to_other(intf, ethernet_frame)
            return True

    def send_ping_from_node(self, node_name, intf_name, dst_ip):
        """Sends a ping from the request node's specified interface.  True is
        returned on success; otherwise a string describing the error is returned."""
        ret = self.get_node_and_intf_with_link(node_name, intf_name)
        if isinstance(ret, basestring):
            return ret
        else:
            _, intf = ret
            mac_dst = intf.link.get_other(intf).mac
            mac_src = intf.mac
            mac_type = '\x08\x00'
            ethernet_hdr = mac_dst + mac_src + mac_type
            src_ip = intf.ip
            ip_hdr = Packet.cksum_ip_hdr('\x45\x00\x00\x54\x00\x00\x40\x00\x40\x01\x00\x00' + src_ip + dst_ip)
            icmp_hdr = Packet.cksum_icmp_pkt('\x08\x00\x00\x00\x00\x00\x00\x01')
            icmp_data = '\x00\x01\x02\x03\x04\x05\x06\x07' * 8  # 56 bytes
            ethernet_frame = ethernet_hdr + ip_hdr + icmp_hdr + icmp_data
            intf.link.send_to_other(intf, ethernet_frame)
            return True

    def send_packet_to_gateway(self, ethernet_frame):
        """Sends an Ethernet frame to the gateway; the destination MAC address
        is set appropriately."""
        if self.gw_intf_to_first_hop and self.raw_socket:
            mac_dst = self.gw_intf_to_first_hop.mac
            new_eth_frame = mac_dst + ethernet_frame[6:]
            self.raw_socket.send(new_eth_frame)

    def is_active(self):
        """Returns true if any clients are connected."""
        return len(self.clients) > 0

    def is_arp_cache_valid(self):
        """Returns True if the ARP cache entry to the first hop is valid."""
        return time.time() - self.last_arp_translation <= ARP_CACHE_TIMEOUT

    def is_ok_to_send_arp_request(self):
        """Returns True if a reasonable amount of time has passed since the
        last ARP request was sent."""
        return time.time() - self.last_arp_translation_request >= 5 # 5 seconds

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
            path = WEB_SERVER_ROOT_WWW + dn.webserver.path_to_serve.get_ascii_path()
            return WebServer(topo, dn.name, path)
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
            assert False, 'intf %s is not attached to this link %s' % (intf, self)

    def send_to_other(self, intf_from, packet):
        """Sends the packet out of the specified interface.  This triggers
        handle_packet() to be called on the owner of the receiving interface.
        The packet may be randomly discarded if lossiness is greater than zero."""
        if self.lossiness==0.0 or random.random()>self.lossiness:
            intf_to = self.get_other(intf_from)
            intf_to.owner.handle_packet(intf_to, packet)

    def __str__(self):
        return '%s:%s <--> %s:%s' % (self.intf1.owner.name, self.intf1.name,
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
        assert departing_intf in self.interfaces, '%s: intf %s does not belong to %s' % (self.topo, departing_intf, self.str_all())
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
        if pkt.mac_dst != intf.mac and not (pkt.is_valid_arp() and pkt.mac_dst=='\xFF\xFF\xFF\xFF\xFF\xFF'):
            logging.debug('%s dropping packet (not to my mac addr %s): %s' % (self.di(), addrstr(intf.mac), pktstr(packet)))
        elif pkt.is_valid_ipv4():
            self.handle_ipv4_packet(intf, pkt)
        elif pkt.is_valid_arp():
            self.handle_arp_packet(intf, pkt)
        else:
            logging.debug('%s discarding packet which is neither valid IPv4 nor ARP' % self.di())

    def handle_arp_packet(self, intf, pkt):
        """Respond to arp if it is a request for the mac address of intf's IP."""
        if pkt.arp_type != '\x00\x01': # only handle ARP REQUESTs
            logging.debug('%s ignoring ARP which is not a request' % self.di())
            return

        # is the ARP request asking about THIS interface on broadcast dha?
        if pkt.dpa==intf.ip and pkt.mac_dst=='\xFF\xFF\xFF\xFF\xFF\xFF':
            # send it back to the requester (reverse src/dst, copy in our mac addr)
            reply_eth = pkt.get_reversed_eth(new_mac_dst=intf.mac)
            reply_arp = pkt.arp[0:7] + '\x02' + intf.mac + intf.ip + pkt.sha + pkt.spa
            reply = reply_eth + reply_arp
            logging.debug('%s replying to ARP request: %s' % (self.di(), pktstr(reply)))
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
                new_icmp = ProtocolHelper.Packet.cksum_icmp_pkt('\x00' + icmp[1:]) # change to echo reply type
                echo_reply = new_eth + new_ip + new_icmp
                logging.debug('%s replying to echo request: %s' % (self.di(), pktstr(echo_reply)))
                self.send_packet(intf, echo_reply)
            else:
                logging.debug('%s ignoring ICMP which is not an echo request' % self.di())
        else:
            self.handle_non_icmp_ip_packet_to_self(intf, pkt)

    def handle_non_icmp_ip_packet_to_self(self, intf, pkt):
        """Handles IP packets which are not ICMP packets by replying with a
        protocol unreachable ICMP message."""
        dst_unreach = pkt.generate_complete_icmp_dst_unreach()
        logging.debug('%s sending dst unreachable in response to non-ICMP IP packet: %s' % (self.di(), pktstr(dst_unreach)))
        self.send_packet(intf, dst_unreach)

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
            self.topo.stats.note_pkt_to_client(len(packet))
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
            if not MAY_FORWARD_TO_PRIVATE_IPS and self.__is_private_address(dst_ip):
                logging.debug('%s ignoring IP packet to private address space: %s' % (self.di(), inet_ntoa(dst_ip)))
                return

        if len(packet) >= 42 and packet[12:14] == '\x08\06' and self.topo.gw_intf_to_first_hop:
            pkt = ProtocolHelper.Packet(packet)
            if pkt.is_arp_reply() and pkt.dha == self.topo.gw_intf_to_first_hop.mac:
                logging.debug('%s: handling ARP reply from first hop to gateway' % self.di())
                self.topo.update_arp_translation(pkt.sha)
                return

        # forward packet out to the real network
        if self.raw_socket:
            try:
                logging.debug('%s sending packet out to the real world: %s' % (self.di(), pktstr(packet)))
                self.topo.stats.note_pkt_from_topo(len(packet))
                self.raw_socket.send(packet)
            except socket.error:
                # this is recoverable - the network may come back up
                log_exception(logging.WARN,
                              'unable to forward packet to the real network')

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
    def __init__(self, topo, name, path_to_serve):
        BasicNode.__init__(self, topo, name)
        self.http_server = HTTPServer(TCPServer.ANY_PORT, path_to_serve)

    @staticmethod
    def get_type_str():
        return 'Web Server'

    def handle_non_icmp_ip_packet_to_self(self, intf, pkt):
        """If pkt is to an HTTP_PORT, then the packet is handed off to the HTTP
        server.  Otherwise, the default superclass implementation is called."""
        if pkt.is_valid_tcp():
            if is_http_port(pkt.tcp_dst_port):
                self.handle_http_request(intf, pkt)
                return
        BasicNode.handle_non_icmp_ip_packet_to_self(self, intf, pkt)

    def handle_http_request(self, intf, pkt):
        """Forward the received packet from an HTTP client to the web server."""
        tcp_conn = self.http_server.handle_tcp(pkt)
        if tcp_conn:
            tcp_pts = tcp_conn.get_packets_to_send()
            if tcp_pts:
                for tcp, data in tcp_pts:
                    eth = pkt.get_reversed_eth()
                    ip = pkt.get_reversed_ip(new_ttl=64, new_tlen=pkt.ip_hlen+len(tcp)+len(data))
                    pkt_out = eth + ip + Packet.cksum_tcp_hdr(ip, tcp, data) + data
                    logging.debug('%s sending packet from HTTP server: %s' % (self, pktstr(pkt_out)))
                    intf.link.send_to_other(intf, pkt_out)

    def __str__(self):
        ps = ' serving:%s' % self.http_server.get_path_being_served()
        return BasicNode.__str__(self) + ps
