#!/usr/bin/env python
"""Command-line program for interacting with VNS topologies."""

import cmd
import hashlib
from optparse import OptionParser
import os
import socket
import sys

from ltprotocol.ltprotocol import LTTwistedClient
from twisted.internet import reactor

from TopologyInteractionProtocol import TI_DEFAULT_PORT, TI_PROTOCOL, TIOpen, TIPacket, TIPingFromRequest, TIBadNodeOrPort, TIBanner, TITap
from VNSProtocol import VNSAuthRequest, VNSAuthReply, VNSAuthStatus

# whether this program is in the process of terminating
TERMINATE = False

# completions for sr topologies
PING_NODE_COMPLETIONS = ['server1', 'server2']
NODE_COMPLETIONS = PING_NODE_COMPLETIONS + ['vrhost:eth0', 'vrhost:eth1', 'vrhost:eth2']

def get_node_and_port(x):
    """Returns a (node,port) pair from a string in the format <node>[:<port>]."""
    out = x.split(':')
    if len(out) == 1:
        return (x, 'eth0')
    elif len(out) != 2:
        raise ValueError("node must be specified in the form <name>[:<port>]")
    else:
        return out

class TapTracker(object):
    def __init__(self, ping_req):
        """Constructs a new TapTracker to wait for a reply for ping_req."""
        self.node_name = ping_req.node_name
        self.intf_name = ping_req.intf_name
        self.num_replies_outstanding = 0

        # maps destination IPs to # replies outstanding
        self.waiting_for_replies_from = {}
        self.new_echo_request_sent(ping_req)

    def is_done(self):
        """Returns True if no more replies are expected."""
        return self.num_replies_outstanding == 0

    def new_echo_request_sent(self, ping_req):
        """Adds an additional echo request to wait for a response for."""
        v = self.waiting_for_replies_from.get(ping_req.dst_ip, 0)
        self.waiting_for_replies_from[ping_req.dst_ip] = v + 1

    def note_reply(self, from_ip):
        """Indicates that an echo reply has been received from the specified IP.
        Returns True if this TapTracker was expecting this reply."""
        try:
            n = self.waiting_for_replies_from[from_ip]
            if n > 0:
                self.waiting_for_replies_from[from_ip] = n - 1
                self.num_replies_outstanding -= 1
                return True
        except KeyError:
            pass # don't care about echo replies we didn't ask for
        return False

def setup_tap_then_send_ping(conn, ping_req):
    """Starts an IP tap on the node/intf which the ping is requested from and
    then sings the ping request.  Also sets up a TapTracker to monitor the tap
    and track replies so we know when we can uninstall the tap."""
    n, i = ping_req.node_name, ping_req.intf_name
    key = (n, i)
    try:
        tt = conn.tap_trackers[key]
        tt.new_echo_request_sent(ping_req)
    except KeyError:
        conn.tap_trackers[key] = TapTracker(ping_req)

    conn.send(TITap(n, i, True, False, True))
    conn.send(ping_req)

class TopologyInteractor(cmd.Cmd):
    prompt = '>>> '

    def __init__(self, ti_conn):
        cmd.Cmd.__init__(self)
        self.conn = ti_conn

    def do_ping(self, line):
        """ping <dst> from <node>: Sends a ping FROM node to dst.
        """
        args = line.split()
        if len(args) != 3:
            print 'syntax error: ping expects this syntax: <dst> from <node>'
        elif args[1] != "from":
            print "syntax error: expected argument 2 to be 'from'"
        else:
            dst, _, node = args
            try:
                name, port = get_node_and_port(node)
            except ValueError, e:
                print e
                return
            try:
                ping_req = TIPingFromRequest(name, port, dst)
            except socket.gaierror, e: # thrown if dst cannot be converted to an IP
                print e
                return
            reactor.callFromThread(setup_tap_then_send_ping, self.conn, ping_req)
            dst_ip = socket.inet_ntoa(ping_req.dst_ip)
            extra = ''
            if dst_ip != dst:
                extra = ' (%s)' % dst_ip
            print 'requested that %s send a ping to %s%s' % (node, dst, extra)

    def complete_ping(self, text, line, begidx, endidx):
        splits = (line+'x').split(' ')
        if len(splits)==3:
            completions = ['from']
        elif len(splits)<3 or len(splits)>4:
            completions = []
        elif not text:
            completions = PING_NODE_COMPLETIONS[:]
        else:
            completions = [n for n in PING_NODE_COMPLETIONS if n.startswith(text)]
        return completions

    def do_EOF(self, line):
        """Terminates this session."""
        print
        reactor.callFromThread(reactor.stop)
        return True

    def emptyline(self):
        pass

    def onecmd(self, s):
        if TERMINATE:
            return True
        else:
            return cmd.Cmd.onecmd(self, s)

def main(argv=sys.argv[1:]):
    """Parses command-line arguments and then runs the TI client."""
    usage = """usage: %prog [options] -t <TOPO_ID>
Connects to the VNS Topology Interaction service."""
    parser = OptionParser(usage)
    parser.add_option("-s", "--server",
                      default='vns-2.stanford.edu',
                      help="VNS server IP address or hostname [default:%default]")
    parser.add_option("-t", "--topo_id", # specified as an option for consistency with sr args
                      default=-1, type="int",
                      help="Topology ID to interact with")
    parser.add_option("-u", "--username",
                      default=os.getlogin(),
                      help="VNS username [default:%default]")
    parser.add_option("-a", "--auth_key_file",
                      default='auth_key',
                      help="File containing your auth key [default:%default]")

    (options, args) = parser.parse_args(argv)
    if len(args) > 0:
        parser.error("too many arguments")

    if options.topo_id == -1:
        parser.error("-t (topology id to interact with) must be specified")

    # get the auth key
    try:
        fp = open(options.auth_key_file, 'r')
        auth_key = fp.read()
        auth_key = auth_key[:len(auth_key)-1] # remove trailing \n
        fp.close()
    except IOError, e:
        print 'Unable to load authentication key from %s: %s' % (options.auth_key_file, e)
        return

    # connect to the server and handle messages it sends us
    print 'Connecting to VNS server at %s ...' % options.server
    gc = lambda c : got_connected(c,options.topo_id, options.username, auth_key)
    client = LTTwistedClient(TI_PROTOCOL, msg_received, gc, got_disconnected, False)
    client.connect(options.server, TI_DEFAULT_PORT)
    reactor.run()

def msg_received(conn, msg):
    """Handles messages received from the TI server.  Starts the
    TopologyInteractor command-line interface once authentication is complete."""
    if msg is not None:
        if msg.get_type() == VNSAuthRequest.get_type():
            print 'Authenticating as %s' % conn.username
            sha1_of_salted_pw = hashlib.sha1(msg.salt + conn.auth_key).digest()
            conn.send(VNSAuthReply(conn.username, sha1_of_salted_pw))
        elif msg.get_type() == VNSAuthStatus.get_type():
            print 'got auth status'
            if msg.auth_ok:
                print 'Authentication successful.'
                conn.send(TIOpen(conn.tid))
                reactor.callInThread(TopologyInteractor(conn).cmdloop)
            else:
                print 'Authentication failed.'
        elif msg.get_type() ==  TIBadNodeOrPort.get_type():
            txt = str(msg)
            if conn.prev_bn_msg == txt:
                conn.prev_bn_msg = None # only stop it once
            else:
                if conn.prev_bn_msg != None:
                    print '***%s!=%s'%(conn.prev_bn_msg,txt)
                conn.prev_bn_msg = txt
                print '\n', txt
        elif msg.get_type() ==  TIBanner.get_type():
            print '\n', msg.msg
        elif msg.get_type() ==  TIPacket.get_type():
            got_tapped_packet(conn, msg)
        else:
            print 'unexpected TI message received: %s' % msg

def got_connected(conn, tid, username, auth_key):
    print 'Connected!'
    conn.tid = tid
    conn.username = username
    conn.auth_key = auth_key
    conn.tap_trackers = {} # key=(node,intf) => maps to TapTracker
    conn.prev_bn_msg = None

def got_disconnected(conn):
    print 'Disconnected!'
    try:
        reactor.stop()
    except:
        pass
    global TERMINATE
    TERMINATE = True

def got_tapped_packet(conn, packet_msg):
    # check to see if the tap got an ICMP Echo Reply
    pkt = packet_msg.ethernet_frame
    if len(pkt)>=14+20+8 and pkt[12:14]=='\x08\x00' and pkt[23]=='\x01' and pkt[34]=='\x00':
        # check to see if we were waiting for a reply to a ping we sent
        n, i = (packet_msg.node_name, packet_msg.intf_name)
        key = (n, i)
        try:
            tt = conn.tap_trackers[key]
        except KeyError:
            return
        src_ip = pkt[26:30]
        if tt.note_reply(src_ip):
            print '%s:%s received ECHO REPLY from %s' % (n, i, socket.inet_ntoa(src_ip))

        # stop the tap if we aren't listening for any more replies from (n,i)
        if tt.is_done():
            del conn.tap_trackers[key]
            conn.send(TITap(n, i, False))

if __name__ == "__main__":
    main()
