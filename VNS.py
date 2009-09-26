"""The VNS simulator."""

import errno
import logging, logging.config
import os
import socket
import sys

from pcapy import open_live, PcapError
from twisted.internet import reactor
from twisted.python.log import PythonLoggingObserver
from twisted.python import log as tlog

from settings import BORDER_DEV_NAME
from LoggingHelper import log_exception, addrstr, pktstr
import ProtocolHelper
from Topology import Topology
from TopologyResolver import TopologyResolver
from VNSProtocol import VNS_DEFAULT_PORT, create_vns_server
from VNSProtocol import VNSOpen, VNSClose, VNSPacket
from web.vns import models as db

class VNSSimulator:
    """The VNS simulator.  It gives clients control of nodes in simulated
    topologies."""
    def __init__(self):
        self.topologies = {} # maps active topology ID to its Topology object
        self.resolver = TopologyResolver() # maps MAC/IP addresses to a Topology
        self.clients = {}    # maps active conn to the topology ID it is conn to
        self.server = create_vns_server(VNS_DEFAULT_PORT,
                                        self.handle_recv_msg,
                                        self.handle_client_disconnected)
        if BORDER_DEV_NAME:
            self.__start_raw_socket(BORDER_DEV_NAME)
            # run pcap in another thread (it will run forever)
            reactor.callInThread(self.__run_pcap, BORDER_DEV_NAME)
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
            logging.debug('recv VNS msg: %s', vns_msg)
            if vns_msg.get_type() == VNSOpen.get_type():
                self.handle_open_msg(conn, vns_msg)
            elif vns_msg.get_type() == VNSClose.get_type():
                self.handle_close_msg(conn)
            elif vns_msg.get_type() == VNSPacket.get_type():
                self.handle_packet_msg(conn, vns_msg)

    def start_topology(self, tid):
        """Handles starting up the specified topology id.  Returns None if it
        cannot be started."""
        try:
            topo = Topology(tid, self.raw_socket)
        except db.Topology.DoesNotExist, db.IPAssignment.DoesNotExist:
            return None
        except:
            log_exception(logging.ERROR, 'topology instantiation unexpectedly failed')
            return None

        self.resolver.register_topology(topo)
        self.topologies[tid] = topo
        return topo

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
                self.resolver.unregister_topology(topo)
                del self.topologies[tid]

    def handle_open_msg(self, conn, open_msg):
        # get the topology the client is trying to connect to
        tid = open_msg.topo_id
        logging.info('new client %s connected to topology %d' % (conn, tid))
        try:
            topo = self.topologies[tid]
        except KeyError:
            topo = self.start_topology(tid)
            if topo is None:
                msg = 'requested topology (%d) does not exist or could not be instantiated'
                self.terminate_connection(conn, msg % tid)
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
            return

        if ret is not True: # bad interface name was given
            self.terminate_connection(conn, ret)

    def cleanup_and_exit(self):
        """Cleanly terminate connected clients and then forcibly terminate the program."""
        logging.info('VNS simulator shutting down')
        for conn in self.clients.keys():
            self.terminate_connection(conn, 'the simulator is shutting down')
        os._exit(0) # force the termination (otherwise the pcap thread keeps going)

class NoOpTwistedLogger:
    """Discards all logging messages (our custom handler takes care of them)."""
    def flush(self):
        pass
    def write(self, x):
        pass

def main():
    logging.config.fileConfig('logging.conf')
    logging.info('VNS Simulator starting up')
    PythonLoggingObserver().start() # log twisted messages too
    tlog.startLogging(NoOpTwistedLogger(), setStdout=False)
    sim = VNSSimulator()
    reactor.addSystemEventTrigger("before", "shutdown", sim.cleanup_and_exit)
    reactor.run()

if __name__ == "__main__":
    main()
