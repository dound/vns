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

from TopologyInteractionProtocol import TI_DEFAULT_PORT, TI_PROTOCOL, TIOpen, TIPingFromRequest, TIBadNodeOrPort, TIBanner
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
            reactor.callFromThread(self.conn.send, ping_req)
            dst_ip = socket.inet_ntoa(ping_req.dst_ip)
            extra = ''
            if dst_ip != dst:
                extra = ' (%s)' % dst_ip
            print 'requested that %s send a ping to %s%s' % (node, dst, extra)

    def complete_ping(self, text, line, begidx, endidx):
        splits = (line+'x').split(' ')
        if len(splits)<3 or len(splits)>4:
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
    mr = lambda c,m : msg_received(c,m,options.topo_id, options.username, auth_key)
    client = LTTwistedClient(TI_PROTOCOL, mr, got_connected, got_disconnected, False)
    client.connect(options.server, TI_DEFAULT_PORT)
    reactor.run()

def msg_received(conn, msg, tid, username, auth_key):
    """Handles messages received from the TI server.  Starts the
    TopologyInteractor command-line interface once authentication is complete."""
    if msg is not None:
        if msg.get_type() == VNSAuthRequest.get_type():
            print 'Authenticating as %s' % username
            sha1_of_salted_pw = hashlib.sha1(msg.salt + auth_key).digest()
            conn.send(VNSAuthReply(username, sha1_of_salted_pw))
        elif msg.get_type() == VNSAuthStatus.get_type():
            print 'got auth status'
            if msg.auth_ok:
                print 'Authentication successful.'
                conn.send(TIOpen(tid))
                reactor.callInThread(TopologyInteractor(conn).cmdloop)
            else:
                print 'Authentication failed.'
        elif msg.get_type() ==  TIBadNodeOrPort.get_type():
            print '\n', msg
        elif msg.get_type() ==  TIBanner.get_type():
            print '\n', msg
        else:
            print 'unexpected TI message received: %s' % msg

def got_connected(conn):
    print 'Connected!'

def got_disconnected(conn):
    print 'Disconnected!'
    try:
        reactor.stop()
    except:
        pass
    global TERMINATE
    TERMINATE = True

if __name__ == "__main__":
    main()
