"""The VNS simulator."""

import datetime
import errno
import hashlib
import logging, logging.config
import os
from os.path import dirname
import socket
import sys

from pcapy import open_live, PcapError
from twisted.internet import reactor
from twisted.python.log import PythonLoggingObserver
from twisted.python import log as tlog

from settings import BORDER_DEV_NAME, PCAP_FILTER
import AddressAllocation
from LoggingHelper import log_exception, addrstr, pktstr
import ProtocolHelper
from Topology import Topology, TopologyCreationException
from TopologyInteractionProtocol import TI_DEFAULT_PORT, create_ti_server, TIOpen, TIPacket, TIBanner
from TopologyResolver import TopologyResolver
from VNSProtocol import VNS_DEFAULT_PORT, create_vns_server
from VNSProtocol import VNSOpen, VNSClose, VNSPacket, VNSOpenTemplate, VNSRtable, VNSAuthRequest, VNSAuthReply, VNSAuthStatus
from web.vnswww import models as db

class VNSSimulator:
    """The VNS simulator.  It gives clients control of nodes in simulated
    topologies."""
    def __init__(self):
        # close out any hanging stats records (shouldn't be any unless the
        # server was shutdown abnormally with no chance to cleanup)
        db.StatsTopology.objects.filter(active=True).update(active=False)

        self.topologies = {} # maps active topology ID to its Topology object
        self.resolver = TopologyResolver() # maps MAC/IP addresses to a Topology
        self.clients = {}    # maps active conn to the topology ID it is conn to
        self.server_old = create_vns_server(12345,
                                        self.handle_recv_msg,
                                        self.handle_new_client_old,
                                        self.handle_client_disconnected)
        self.server = create_vns_server(VNS_DEFAULT_PORT,
                                        self.handle_recv_msg,
                                        self.handle_new_client,
                                        self.handle_client_disconnected)
        self.ti_clients = {} # maps active TI conns to the topology ID it is conn to
        self.ti_server = create_ti_server(TI_DEFAULT_PORT,
                                          self.handle_recv_ti_msg,
                                          self.handle_ti_client_disconnected)
        if BORDER_DEV_NAME:
            self.__start_raw_socket(BORDER_DEV_NAME)
            # run pcap in another thread (it will run forever)
            reactor.callInThread(self.__run_pcap, BORDER_DEV_NAME)
        else:
            self.raw_socket = None

        self.periodic_callback()

    def __run_pcap(self, dev):
        """Start listening for packets coming in from the outside world."""
        MAX_LEN      = 1514    # max size of packet to capture
        PROMISCUOUS  = 1       # promiscuous mode?
        READ_TIMEOUT = 100     # in milliseconds
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

    def periodic_callback(self):
        for topo in self.topologies.values():
            topo.save_stats()
        reactor.callLater(60, self.periodic_callback)

    def handle_packet_from_outside(self, packet):
        """Forwards packet to the appropriate simulation, if any."""
        if len(packet) < 14:
            return # too small to even have an Ethernet header

        # determine which topology(ies) should receive this packet
        pkt = ProtocolHelper.Packet(packet)
        if pkt.is_valid_ipv4():
            topos = self.resolver.resolve_ip(pkt.ip_dst, pkt.ip_src)
            str_addr = 'dst=%s src=%s' % (addrstr(pkt.ip_dst), addrstr(pkt.ip_src))
            rewrite_dst_mac = True
        elif pkt.is_dst_mac_broadcast():
            return # ignore broadcasts
        else:
            topos = self.resolver.resolve_mac(pkt.mac_dst)
            str_addr = 'dst=%s' % addrstr(pkt.mac_dst)
            rewrite_dst_mac = False

        # forward the packet to the appropriate topology(ies)
        if topos:
            logging.debug('sniffed raw packet to %s (topology %s): %s' %
                          (str_addr, ','.join([str(t.id) for t in topos]), pktstr(packet)))
            for topo in topos:
                topo.handle_incoming_packet(packet, rewrite_dst_mac)

    def handle_recv_msg(self, conn, vns_msg):
        if vns_msg is not None:
            logging.debug('recv VNS msg: %s' % vns_msg)
            if vns_msg.get_type() == VNSAuthReply.get_type():
                self.handle_auth_reply(conn, vns_msg)
                return
            elif not conn.vns_authorized:
                logging.warning('received non-auth-reply from unauthenticated user %s: terminating the user' % conn)
                self.terminate_connection(conn, 'simulator expected authentication reply')
            # user is authenticated => any other messages are ok
            elif vns_msg.get_type() == VNSOpen.get_type():
                self.handle_open_msg(conn, vns_msg)
            elif vns_msg.get_type() == VNSClose.get_type():
                self.handle_close_msg(conn)
            elif vns_msg.get_type() == VNSPacket.get_type():
                self.handle_packet_msg(conn, vns_msg)
            elif vns_msg.get_type() == VNSOpenTemplate.get_type():
                self.handle_open_template_msg(conn, vns_msg)
            else:
                logging.debug('unexpected VNS message received: %s' % vns_msg)

    def start_topology(self, tid, client_ip, username):
        """Handles starting up the specified topology id.  Returns a 2-tuple.
        The first element is None and the second is a string if an error occurs;
        otherwise the first element is the topology."""
        try:
            topo = Topology(tid, self.raw_socket, client_ip, username)
        except TopologyCreationException as e:
            return (None, str(e))
        except db.Topology.DoesNotExist:
            return (None, 'topology %d does not exist' % tid)
        except db.IPAssignment.DoesNotExist:
            return (None, 'topology %d is missing an IP assignment' % tid)
        except:
            msg = 'topology instantiation unexpectedly failed'
            log_exception(logging.ERROR, msg)
            return (None, msg)

        if topo.has_gateway():
            self.resolver.register_topology(topo)
        self.topologies[tid] = topo
        return (topo, None)

    def terminate_connection(self, conn, why, notify_client=True, log_it=True, lvl=logging.INFO):
        """Terminates the client connection conn.  This event will be logged
        unless log_it is False.  If notify_client is True, then the client will
        be sent a VNSClose message with an explanation."""
        # terminate the client
        if conn.connected:
            if notify_client:
                conn.send(VNSClose(why))
            conn.transport.loseConnection()

        if log_it:
            logging.log(lvl, 'terminating client (%s): %s' % (conn, why))

        # cleanup client and topology info
        tid = self.clients.get(conn)
        if tid is not None:
            del self.clients[conn]
            topo = self.topologies[tid]
            topo.client_disconnected(conn)
            if not topo.is_active():
                if topo.has_gateway():
                    self.resolver.unregister_topology(topo)
                del self.topologies[tid]
                topo_stats = topo.get_stats()
                topo_stats.active = False
                deltaT = datetime.datetime.now() - topo_stats.time_connected
                deltaTsecs = deltaT.seconds + 60*60*24*deltaT.days
                topo_stats.total_time_connected_sec = deltaTsecs
                topo_stats.save()

    def handle_open_msg(self, conn, open_msg):
        # get the topology the client is trying to connect to
        self.handle_connect_to_topo(conn, open_msg.topo_id, open_msg.user, open_msg.vhost)

    def handle_connect_to_topo(self, conn, tid, username, vhost):
        logging.info('client %s connected to topology %d' % (conn, tid))
        try:
            topo = self.topologies[tid]
        except KeyError:
            client_ip = conn.transport.getPeer().host
            (topo, err_msg) = self.start_topology(tid, client_ip, username)
            if topo is None:
                self.terminate_connection(conn, err_msg)
                return

        # try to connect the client to the requested node
        self.clients[conn] = tid
        requested_name = vhost.replace('\x00', '')
        user = conn.vns_user_profile.user if conn.vns_user_profile else None
        ret = topo.connect_client(conn, user, requested_name)
        if not ret.is_success():
            self.terminate_connection(conn, ret)
        if ret.prev_client:
            self.terminate_connection(ret.prev_client,
                                      'a new client (%s) has connected to the topology' % conn)

    def handle_open_template_msg(self, conn, ot):
        try:
            template = db.TopologyTemplate.objects.get(name=ot.template_name)
        except db.TopologyTemplate.DoesNotExist:
            self.terminate_connection(conn, "template '%s' does not exist" % ot.template_name)
            return

        # find an IP block to allocate IPs from for this user
        blocks = db.IPBlock.objects.filter(org=conn.vns_user_profile.org)
        if not blocks:
            self.terminate_connection(conn, "your organization (%s) has no available IP blocks" % conn.vns_user_profile.org)
            return
        ip_block_from = blocks[0]

        err_msg, topo, alloc, tree = AddressAllocation.instantiate_template(conn.vns_user_profile.user,
                                                                            template,
                                                                            ip_block_from,
                                                                            ot.get_src_filters(),
                                                                            True, True)
        if err_msg:
            self.terminate_connection(conn, err_msg)
        else:
            rtable_msg = VNSRtable(ot.vrhost, VNSSimulator.build_rtable(topo))
            conn.send(rtable_msg)
            logging.debug('Sent client routing table message: %s' % rtable_msg)
            who = conn.vns_user_profile.user.username
            self.handle_connect_to_topo(conn, topo.id, who, ot.vrhost)

    @staticmethod
    def build_rtable(topo):
        # TODO: write this function for real; just a quick hack for now
        s1 = db.IPAssignment.objects.get(topology=topo, port__node=db.Node.objects.get(template=topo.template, name='Server 1'))
        s2 = db.IPAssignment.objects.get(topology=topo, port__node=db.Node.objects.get(template=topo.template, name='Server 2'))
        return '\n'.join(['0.0.0.0  172.24.74.17  0.0.0.0  eth0',
                          '%s  %s  255.255.255.254  eth1' % (s1.ip, s1.ip),
                          '%s  %s  255.255.255.254  eth2' % (s2.ip, s2.ip)])

    def handle_new_client_old(self, conn):
        logging.debug("Old style client %s connected: bypassing auth" % conn)
        conn.vns_auth_salt = None
        conn.vns_authorized = True
        conn.vns_user_profile = None

    def handle_new_client(self, conn):
        """Sends an authentication request to the new user."""
        logging.debug("client %s connected: sending auth request" % conn)
        conn.vns_auth_salt = os.urandom(20)
        conn.vns_authorized = False
        conn.vns_user_profile = None
        conn.send(VNSAuthRequest(conn.vns_auth_salt))

    def handle_auth_reply(self, conn, ar):
        if not conn.vns_auth_salt:
            msg = 'unexpectedly received authentication reply from conn_user=%s ar_user=%s at %s'
            self.terminate_connection(conn, msg % (conn.vns_user_profile, ar.username, conn))
            return

        try:
            up = db.UserProfile.objects.get(user__username=ar.username)
        except db.UserProfile.DoesNotExist:
            logging.info('unrecognized username tried to login: %s' % ar.username)
            self.terminate_connection(conn, "authentication failed")
            return

        expected = hashlib.sha1(conn.vns_auth_salt + str(up.get_sim_auth_key())).digest()
        if ar.ssp != expected:
            logging.info('user %s provided an incorrect password' % ar.username)
            self.terminate_connection(conn, "authentication failed")
        else:
            conn.vns_auth_salt = None # only need one auth reply
            conn.vns_authorized = True
            conn.vns_user_profile = up
            msg = 'authenticated %s as %s' % (conn, ar.username)
            conn.send(VNSAuthStatus(True, msg))

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
            return

        if ret is not True: # bad interface name was given
            self.terminate_connection(conn, ret)

    def cleanup_and_exit(self):
        """Cleanly terminate connected clients and then forcibly terminate the program."""
        logging.info('VNS simulator shutting down')
        for conn in self.clients.keys():
            self.terminate_connection(conn, 'the simulator is shutting down')
        os._exit(0) # force the termination (otherwise the pcap thread keeps going)

    def handle_recv_ti_msg(self, conn, ti_msg):
        if ti_msg is not None:
            logging.debug('recv VNS TI msg: %s' % ti_msg)
            if ti_msg.get_type() == TIOpen.get_type():
                self.handle_ti_open_msg(conn, ti_msg)
            elif ti_msg.get_type() == TIPacket.get_type():
                self.handle_ti_packet_msg(conn, ti_msg)
            else:
                logging.debug('unexpected VNS TI message received: %s' % ti_msg)

    def handle_ti_open_msg(self, conn, open_msg):
        tid = open_msg.topo_id
        if not self.topologies.has_key(tid):
            self.terminate_ti_connection(conn, 'Topology %d is not currently active' % tid)
        else:
            self.ti_clients[conn] = tid

    def handle_ti_packet_msg(self, conn, pm):
        try:
            tid = self.ti_clients[conn]
        except KeyError:
            self.terminate_ti_connection(conn, 'no topology mapping known (forgot to send TIOpen?)')
            return

        try:
            topo = self.topologies[tid]
        except KeyError:
            self.terminate_ti_connection(conn, 'topology %d is no longer active' % tid)
            return

        ret = topo.send_packet_from_node(pm.node_name, pm.intf_name, pm.ethernet_frame)
        if ret != True:
            self.terminate_ti_connection(conn, ret)

    def handle_ti_client_disconnected(self, conn):
        self.terminate_ti_connection(conn,
                                     'client disconnected (%s)' % conn,
                                     notify_client=False)

    def terminate_ti_connection(self, conn, why, notify_client=True, log_it=True, lvl=logging.INFO):
        """Terminates the TI client connection conn.  This event will be logged
        unless log_it is False.  If notify_client is True, then the client will
        be sent a TIBanner message with an explanation."""
        # terminate the client
        if conn.connected:
            if notify_client:
                conn.send(TIBanner(why))
            conn.transport.loseConnection()

        if log_it:
            logging.log(lvl, 'terminating TI client (%s): %s' % (conn, why))

        # cleanup TI client info
        tid = self.ti_clients.get(conn)
        if tid is not None:
            del self.ti_clients[conn]

def sha1(s):
    """Return the SHA1 digest of the string s"""
    d = hashlib.sha1()
    d.update(s)
    return d.digest()

class NoOpTwistedLogger:
    """Discards all logging messages (our custom handler takes care of them)."""
    def flush(self):
        pass
    def write(self, x):
        pass

def main():
    dir = dirname(__file__)
    dir = dir if dir else '.'
    logging.config.fileConfig(dir + '/logging.conf')
    logging.info('VNS Simulator starting up')
    PythonLoggingObserver().start() # log twisted messages too
    tlog.startLogging(NoOpTwistedLogger(), setStdout=False)
    sim = VNSSimulator()
    reactor.addSystemEventTrigger("before", "shutdown", sim.cleanup_and_exit)
    reactor.run()

if __name__ == "__main__":
    main()
