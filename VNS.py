"""The VNS simulator."""

import errno
import hashlib
import logging, logging.config
import os
from os.path import dirname
import socket
import sys
from threading import Condition, Lock
from time import sleep, time

from pcapy import open_live, PcapError
from twisted.internet import reactor
from twisted.python.log import PythonLoggingObserver
from twisted.python import log as tlog

from settings import BORDER_DEV_NAME, PCAP_FILTER, MAX_TOPOLOGY_LIFE_SEC, MAX_INACTIVE_TOPOLOGY_LIFE_SEC
import AddressAllocation
from LoggingHelper import log_exception, addrstr, pktstr
import ProtocolHelper
from Topology import Topology, TopologyCreationException
from TopologyInteractionProtocol import TI_DEFAULT_PORT, create_ti_server, TIOpen, TIPacket, TIBanner
from TopologyResolver import TopologyResolver
from VNSProtocol import VNS_DEFAULT_PORT, create_vns_server
from VNSProtocol import VNSOpen, VNSClose, VNSPacket, VNSOpenTemplate, VNSBanner, VNSRtable, VNSAuthRequest, VNSAuthReply, VNSAuthStatus
from web.vnswww import models as db

class VNSSimulator:
    """The VNS simulator.  It gives clients control of nodes in simulated
    topologies."""
    def __init__(self):
        # close out any hanging stats records (shouldn't be any unless the
        # server was shutdown abnormally with no chance to cleanup)
        db.StatsTopology.objects.filter(active=True).update(active=False)

        # free any hanging temporary topologies
        for t in db.Topology.objects.filter(temporary=True):
            AddressAllocation.free_topology(t.id)

        self.topologies = {} # maps active topology ID to its Topology object
        self.resolver = TopologyResolver() # maps MAC/IP addresses to a Topology
        self.clients = {}    # maps active conn to the topology ID it is conn to
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

        # lock used to prevent self.topologies from being *changed* by the main
        # twisted thread while the topology queue service thread is reading it
        self.topologies_lock = Lock()

        # communicates from the main twisted thread to the topology queue
        # service thread that the topologies dictionary has changed
        self.topologies_changed = False

        # The topology queue service thread will wait on this condition for a 
        # a chosen/dequeued job to be finish (so it can pick the next one).
        self.service_condition = Condition()

        # run the topology queue service thread
        reactor.callInThread(self.__run_topology_queue_service_thread)

        self.periodic_callback()

    def __run_pcap(self, dev):
        """Start listening for packets coming in from the outside world."""
        MAX_LEN      = 2000    # max size of packet to capture
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
        logging.info("Listening on %s: net=%s, mask=%s, filter=%s" % (dev, p.getnet(), p.getmask(), PCAP_FILTER))
        p.loop(MAX_PKTS, ph)

    def __run_topology_queue_service_thread(self):
        """Monitors the job queue of each topology and serves them in a round
        robin fashion."""
        # list of queues to service
        local_job_queues_list = []

        while True:
            serviced_a_job = False
            
            # get a copy of the latest topology list in a thread-safe manner
            with self.topologies_lock:
                if self.topologies_changed:
                    local_job_queues_list = [t.job_queue for t in self.topologies.values()]
                    self.topologies_changed = False

            # serve each topology's queue
            for q in local_job_queues_list:
                job = q.start_service()
                while job:
                    # thread safety: run each job from the main twisted event loop
                    self.__return_after_running_job_on_main_thread(job)
                    job = q.task_done()
                    serviced_a_job = True
                    
            # If we didn't do anything this time, then pause for about 50ms (no
            # reason to run up the CPU by repeatedly checking empty queues).
            if not serviced_a_job:
                sleep(0.05)

    def __do_job_then_notify(self, job):
        """Acquires the service_condition lock, runs job, and the notifies all
        threads waiting on service_condition."""
        with self.service_condition:
            job()
            self.service_condition.notifyAll()

    def __return_after_running_job_on_main_thread(self, job):
        """Requests that job be run on the main thread.  Waits on 
        service_condition until it is notified that the job is done."""
        with self.service_condition:
            # ask the main thread to run our job (it cannot start until we release this lock)
            reactor.callFromThread(lambda : self.__do_job_then_notify(job))
            
            # wait for the main thread to finish running the job
            self.service_condition.wait()
            
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
        # save statistics values
        for topo in self.topologies.values():
            stats = topo.get_stats()
            if not stats.save_if_changed() and stats.get_idle_time_sec() > MAX_INACTIVE_TOPOLOGY_LIFE_SEC:
                self.stop_topology(topo, 'topology exceeded maximum idle time (%dsec)' % MAX_INACTIVE_TOPOLOGY_LIFE_SEC)
            elif stats.get_num_sec_connected() > MAX_TOPOLOGY_LIFE_SEC:
                self.stop_topology(topo, 'topology exceeded maximum lifetime (%dsec)' % MAX_TOPOLOGY_LIFE_SEC)

        # see if there is any admin message to be sent to all clients
        try:
            bts = db.SystemInfo.objects.get(name='banner_to_send')
            msg_for_clients = bts.value
            bts.delete()
            logging.info('sending message to clients: %s' % msg_for_clients)
            for conn in self.clients.keys():
                for m in VNSBanner.get_banners(msg_for_clients):
                    conn.send(m)
        except db.SystemInfo.DoesNotExist:
            pass

        # note in the db that the reactor thread is still running
        try:
            latest = db.SystemInfo.objects.get(name='last_alive_time')
        except db.SystemInfo.DoesNotExist:
            latest = db.SystemInfo()
            latest.name = 'last_alive_time'
        latest.value = str(int(time()))
        latest.save()

        reactor.callLater(30, self.periodic_callback)

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
                topo.create_job_for_incoming_packet(packet, rewrite_dst_mac)

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

    def start_topology(self, tid, client_ip, user):
        """Handles starting up the specified topology id.  Returns a 2-tuple.
        The first element is None and the second is a string if an error occurs;
        otherwise the first element is the topology."""
        try:
            topo = Topology(tid, self.raw_socket, client_ip, user)
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
        with self.topologies_lock:
            self.topologies[tid] = topo
            self.topologies_changed = True
        return (topo, None)

    def stop_topology(self, topo, why, notify_client=True, log_it=True, lvl=logging.INFO):
        """Terminates all clients on a particular topology.  This will in turn
        cause the topology to be deactivated."""
        for client_conn in topo.get_clients():
            self.terminate_connection(client_conn, why, notify_client, log_it, lvl)

    def terminate_connection(self, conn, why, notify_client=True, log_it=True, lvl=logging.INFO):
        """Terminates the client connection conn.  This event will be logged
        unless log_it is False.  If notify_client is True, then the client will
        be sent a VNSClose message with an explanation."""
        # terminate the client
        if conn.connected:
            if notify_client:
                for m in VNSClose.get_banners_and_close(why):
                    conn.send(m)
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
                with self.topologies_lock:
                    del self.topologies[tid]
                    self.topologies_changed = True
                topo.get_stats().finalize()
                if topo.is_temporary():
                    AddressAllocation.free_topology(tid)

    def handle_open_msg(self, conn, open_msg):
        # get the topology the client is trying to connect to
        self.handle_connect_to_topo(conn, open_msg.topo_id, open_msg.vhost)

    def handle_connect_to_topo(self, conn, tid, vhost):
        logging.info('client %s connected to topology %d' % (conn, tid))
        try:
            topo = self.topologies[tid]
        except KeyError:
            client_ip = conn.transport.getPeer().host
            (topo, err_msg) = self.start_topology(tid, client_ip, conn.vns_user_profile.user)
            if topo is None:
                self.terminate_connection(conn, err_msg)
                return

        # try to connect the client to the requested node
        self.clients[conn] = tid
        requested_name = vhost.replace('\x00', '')
        user = conn.vns_user_profile.user
        ret = topo.connect_client(conn, user, requested_name)
        if not ret.is_success():
            self.terminate_connection(conn, ret.fail_reason)
        else:
            self.send_motd_to_client(conn)
        if ret.prev_client:
            self.terminate_connection(ret.prev_client,
                                      'a new client (%s) has connected to the topology' % conn)

    def send_motd_to_client(self, conn):
        """Sends a message to a newly connected client, if such a a message is set."""
        # see if there is any admin message to be sent to a client upon connecting
        try:
            msg_for_client = db.SystemInfo.objects.get(name='motd').value
            logging.info('sending message to clients: %s' % msg_for_client)
            for m in VNSBanner.get_banners(msg_for_client):
                conn.send(m)
        except db.SystemInfo.DoesNotExist:
            pass

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
            s2intfnum = '2' if ot.template_name == '1-router 2-server' else '1'
            rtable_msg = VNSRtable(ot.vrhost, VNSSimulator.build_rtable(topo, s2intfnum))
            conn.send(rtable_msg)
            logging.debug('Sent client routing table message: %s' % rtable_msg)
            self.handle_connect_to_topo(conn, topo.id, ot.vrhost)

    @staticmethod
    def build_rtable(topo, s2intfnum):
        # TODO: write this function for real; just a quick hack for now
        s1 = db.IPAssignment.objects.get(topology=topo, port__node=db.Node.objects.get(template=topo.template, name='Server1'))
        s2 = db.IPAssignment.objects.get(topology=topo, port__node=db.Node.objects.get(template=topo.template, name='Server2'))
        return '\n'.join(['0.0.0.0  172.24.74.17  0.0.0.0  eth0',
                          '%s  %s  255.255.255.254  eth1' % (s1.ip, s1.ip),
                          '%s  %s  255.255.255.254  eth%s' % (s2.ip, s2.ip, s2intfnum)])

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
            up = db.UserProfile.objects.get(user__username=ar.username, retired=False)
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
        # see if the admin put a reason for the shutdown in the database
        try:
            why = db.SystemInfo.objects.get(name='shutdown_reason').value
        except db.SystemInfo.DoesNotExist:
            why = 'the simulator is shutting down'

        logging.info('VNS simulator shutting down: %s' % why)
        for conn in self.clients.keys():
            self.terminate_connection(conn, why)
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
