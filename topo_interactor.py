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

from LoggingHelper import pcap_write_header, pcap_write_packet, pktstr
from TopologyInteractionProtocol import *
from VNSProtocol import VNSAuthRequest, VNSAuthReply, VNSAuthStatus

# whether this program is in the process of terminating
TERMINATE = False

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
    client = TIClient(options.topo_id, options.username, auth_key)
    client.connect(options.server, TI_DEFAULT_PORT)
    reactor.run()

class TIClient(LTTwistedClient):
    """Implements methods for handling messages received and events from a
    Topology Interaction protocol client connection."""
    def __init__(self, tid, username, auth_key):
        LTTwistedClient.__init__(self, TI_PROTOCOL, self.msg_received, self.got_connected, self.got_disconnected, False)
        self.conn = None
        self.tid = tid
        self.username = username
        self.auth_key = auth_key
        self.prev_bn_msg = None
        self.tap_trackers = {} # key=(node,intf) => maps to TapTracker

    def msg_received(self, conn, msg):
        """Handles messages received from the TI server.  Starts the
        TopologyInteractor command-line interface once authentication is complete."""
        if msg is not None:
            if msg.get_type() == VNSAuthRequest.get_type():
                print 'Authenticating as %s' % self.username
                sha1_of_salted_pw = hashlib.sha1(msg.salt + self.auth_key).digest()
                conn.send(VNSAuthReply(self.username, sha1_of_salted_pw))
            elif msg.get_type() == VNSAuthStatus.get_type():
                if msg.auth_ok:
                    print 'Authentication successful.'
                    conn.send(TIOpen(self.tid))
                    reactor.callInThread(TopologyInteractor(self).cmdloop)
                else:
                    print 'Authentication failed.'
            elif msg.get_type() ==  TIBadNodeOrPort.get_type():
                txt = str(msg)
                if self.prev_bn_msg == txt:
                    self.prev_bn_msg = None # only stop it once
                else:
                    if self.prev_bn_msg != None:
                        print '***%s!=%s'%(self.prev_bn_msg,txt)
                    self.prev_bn_msg = txt
                    print '\n', txt
            elif msg.get_type() ==  TIBanner.get_type():
                print '\n', msg.msg
            elif msg.get_type() ==  TIPacket.get_type():
                self.got_tapped_packet(msg)
            else:
                print 'unexpected TI message received: %s' % msg

    def got_connected(self, conn):
        print 'Connected!'
        self.conn = conn

    def got_disconnected(self, conn):
        print 'Disconnected!'
        try:
            reactor.stop()
        except:
            pass
        global TERMINATE
        TERMINATE = True

    def got_tapped_packet(self, packet_msg):
        # check to see if we were waiting for a reply to a ping we sent
        n, i = (packet_msg.node_name, packet_msg.intf_name)
        key = (n, i)
        try:
            tt = self.tap_trackers[key]
        except KeyError:
            return

        if tt.got_packet(packet_msg.ethernet_frame):
            src_ip = packet_msg.ethernet_frame[26:30]
            print '%s:%s received ECHO REPLY from %s' % (n, i, socket.inet_ntoa(src_ip))

            # stop the tap if we aren't listening for any more replies from (n,i)
            if tt.is_done():
                del self.tap_trackers[key]
                self.conn.send(TITap(n, i, False))

class TapHandler(object):
    """Contains info about and handles a tap on a particular node:port."""
    def __init__(self, permanent):
        """Constructs a new TapTracker.  If permanent is True, then it continues
        until explicitly disabled.  Otherwise, is_done() will return True
        whenever an echo reply has been received for each new_echo_request_sent()
        call."""
        self.num_replies_outstanding = 0
        self.permanent = permanent
        self.print_recv_packets = False
        self.log_fp = None
        self.waiting_for_replies_from = {} # maps dst IPs to # replies outstanding

    def __del__(self):
        if self.log_fp:
            self.log_fp.close()

    def toggle_screen_logging(self):
        self.print_recv_packets = not self.print_recv_packets

    def set_file_logging(self, filename):
        if not filename:
            self.log_fp = None
        else:
            self.log_fp = open(filename, 'w')
            pcap_write_header(self.log_fp)

    def is_done(self):
        """Returns True if no more replies are expected and this is not a
        permanent tap."""
        return self.num_replies_outstanding==0 and not self.permanent

    def new_echo_request_sent(self, ping_req):
        """Adds an additional echo request to wait for a response for."""
        v = self.waiting_for_replies_from.get(ping_req.dst_ip, 0)
        self.waiting_for_replies_from[ping_req.dst_ip] = v + 1
        self.num_replies_outstanding += 1

    def got_packet(self, pkt):
        """Handles packets received as a result of this tap.  If the packet is
        an echo reply to an echo request we sent, then True is returned."""
        # log the packet if requested
        if self.print_recv_packets:
            print pktstr(pkt, noop=False)
        if self.log_fp:
            pcap_write_packet(self.log_fp, pkt)

        # see if this was an echo reply we were waiting for
        if self.num_replies_outstanding > 0:
            return self.__check_for_echo_reply(pkt)
        return False

    def __check_for_echo_reply(self, pkt):
        if len(pkt)>=14+20+8 and pkt[12:14]=='\x08\x00' and pkt[23]=='\x01' and pkt[34]=='\x00':
            src_ip = pkt[26:30]
            try:
                n = self.waiting_for_replies_from[src_ip]
                if n > 0:
                    self.waiting_for_replies_from[src_ip] = n - 1
                    self.num_replies_outstanding -= 1
                    return True
            except KeyError:
                pass # don't care about echo replies we didn't ask for
            return False

class TopologyInteractor(cmd.Cmd):
    """An interactive command prompt for interacting with a topology."""
    prompt = '>>> '
    TAP_CMDS = ['off', 'screen']
    LINKMOD_CMDS = ['up', 'down']

    # completions for sr topologies
    PING_NODE_COMPLETIONS = ['server1', 'server2']
    NODE_COMPLETIONS = PING_NODE_COMPLETIONS + ['vrhost:eth0', 'vrhost:eth1', 'vrhost:eth2', 'gateway']


    def __init__(self, ti_client):
        cmd.Cmd.__init__(self)
        self.tic = ti_client

    def do_exit(self, line):
        self.do_EOF(line)

    def help_exit(self):
        self.help_EOF()

    def do_linkmod(self, line):
        args = line.split()
        if len(args) != 2:
            print 'syntax error: linkmod expects this syntax: <node>[:intf] <new_state>'
            return
        node, new_state = args
        try:
            n, i = self.get_node_and_port(node)
            if new_state == 'up':
                new_state = 0.0
            elif new_state == 'down':
                new_state = 1.0
            else:
                new_state = float(new_state) / 100.0
                if new_state < 0.0 or new_state > 1.0:
                    raise ValueError('Lossiness must be specified in the range [0.0, 100.0]')
        except ValueError, e:
            print e
            return
        reactor.callFromThread(self.tic.conn.send, TIModifyLink(n, i, new_state))

    def complete_linkmod(self, text, line, begidx, endidx):
        return self.node_completion_helper(text, line, self.LINKMOD_CMDS)

    def help_linkmod(self):
        print '\n'.join(['link <node>[:intf] <new_state>',
                         '  new_state:',
                         '    up         enable the link (0% loss)',
                         '    down       disable the link (100% loss)',
                         '    <float>    enable the link with lossiness (e.g., 5 => 5% loss)'])

    def do_ping(self, line):
        """ping <dst> from <node>[:intf] -- sends a ping FROM node to dst."""
        args = line.split()
        if len(args) != 3:
            print 'syntax error: ping expects this syntax: <dst> from <node>'
        elif args[1] != "from":
            print "syntax error: expected argument 2 to be 'from'"
        else:
            dst, _, node = args
            try:
                name, port = self.get_node_and_port(node)
            except ValueError, e:
                print e
                return
            try:
                ping_req = TIPingFromRequest(name, port, dst)
            except socket.gaierror, e: # thrown if dst cannot be converted to an IP
                print e
                return
            reactor.callFromThread(self.setup_tap_then_send_ping, self.tic, ping_req)
            dst_ip = socket.inet_ntoa(ping_req.dst_ip)
            extra = ''
            if dst_ip != dst:
                extra = ' (%s)' % dst_ip
            print 'requested that %s send a ping to %s%s' % (node, dst, extra)

    @staticmethod
    def setup_tap_then_send_ping(tic, ping_req):
        """Starts an IP tap on the node/intf which the ping is requested from and
        then sings the ping request.  Also sets up a TapTracker to monitor the tap
        and track replies so we know when we can uninstall the tap."""
        n, i = ping_req.node_name.lower(), ping_req.intf_name.lower()
        key = (n, i)
        try:
            tt = tic.tap_trackers[key]
            tt.new_echo_request_sent(ping_req)
        except KeyError:
            tt = TapHandler(False)
            tt.new_echo_request_sent(ping_req)
            tic.tap_trackers[key] = tt
            tic.conn.send(TITap(n, i, True, False, True))
        tic.conn.send(ping_req)

    def complete_ping(self, text, line, begidx, endidx):
        splits = (line+'x').split(' ')
        if len(splits)==3:
            completions = ['from '+s for s in self.PING_NODE_COMPLETIONS]
        elif len(splits)<3 or len(splits)>4:
            completions = []
        else:
            if text:
                completions = [n for n in self.PING_NODE_COMPLETIONS if n.startswith(text)]
            else:
                completions = self.PING_NODE_COMPLETIONS[:]
        return completions

    def do_tap(self, line):
        args = line.split()
        if len(args) != 2:
            print 'syntax error: tap expects this syntax: <node>[:intf] <command>'
            return
        node, cmd = args
        try:
            n, i = self.get_node_and_port(node)
        except ValueError, e:
            print e
            return
        key = (n, i)
        try:
            if cmd == 'off':
                del self.tic.tap_trackers[key]
                reactor.callFromThread(self.tic.conn.send, TITap(n, i, False))
                return
            else:
                tt = self.tic.tap_trackers[key]
                tt.permanent = True
        except KeyError:
            if cmd == 'off':
                print 'There is no tap on %s:%s' % (n, i)
                return
            tt = TapHandler(permanent=True)
            reactor.callFromThread(self.tic.conn.send, TITap(n, i, True))
            self.tic.tap_trackers[key] = tt
        if cmd == 'screen':
            tt.toggle_screen_logging()
        else: # cmd is a filename
            tt.set_file_logging(cmd)

    def complete_tap(self, text, line, begidx, endidx):
        return self.node_completion_helper(text, line, self.TAP_CMDS)

    def help_tap(self):
        print '\n'.join(["tap <node>[:intf] <command>",
                         "  commands:",
                         "     off           deletes the tap",
                         "     screen        toggles the printing of packets the tap receives",
                         "     <filename>    dumps packets the tap receives to a pcap file"])

    def do_EOF(self, line):
        print
        reactor.callFromThread(reactor.stop)
        return True

    def help_EOF(self):
        print 'Terminates this session'

    def help_help(self):
        print "Displays a list of available commands."

    def default(self, line):
        """Ignore lines beginning with '#'.  Print a message about an unknown
        command otherwise."""
        if line.lstrip()[0] != '#':  # line is non-empty
            print 'Unknown command: %s' % line.split(' ')[0]

    def emptyline(self):
        """Empty lines are no-ops - overrides the default which re-executes the
        previous command."""
        pass

    def onecmd(self, s):
        """Runs the command unless the program is terminating."""
        if TERMINATE:
            return True
        else:
            return cmd.Cmd.onecmd(self, s)

    @staticmethod
    def get_node_and_port(x):
        """Returns a (node,port) pair from a string in the format <node>[:<port>]."""
        out = x.split(':')
        if len(out) == 1:
            return (x, 'eth0')
        elif len(out) != 2:
            raise ValueError("node must be specified in the form <name>[:<port>]")
        else:
            return out

    @staticmethod
    def node_completion_helper(text, line, commands):
        """Completion options for commands of the form: <name> <node>[:intf] <commands>"""
        splits = (line+'x').split(' ')
        if len(splits)==2:
            if text:
                completions = [n for n in TopologyInteractor.NODE_COMPLETIONS if n.startswith(text)]
            else:
                completions = TopologyInteractor.NODE_COMPLETIONS[:]
        elif len(splits)==3:
            if text:
                completions = [n for n in commands if n.startswith(text)]
            else:
                completions = commands[:]
        else:
            completions = []
        return completions

if __name__ == "__main__":
    main()
