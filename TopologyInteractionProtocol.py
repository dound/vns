"""Defines the TI protocol and some associated helper functions."""

import struct

from ltprotocol.ltprotocol import LTMessage, LTProtocol, LTTwistedServer

from LoggingHelper import pktstr
from VNSProtocol import strip_null_chars, VNSAuthRequest, VNSAuthReply, VNSAuthStatus

TI_DEFAULT_PORT = 12346
TI_MESSAGES = [VNSAuthRequest, VNSAuthReply, VNSAuthStatus]  # uses same auth messages

class TIOpen(LTMessage):
    @staticmethod
    def get_type():
        return 1

    def __init__(self, topo_id):
        LTMessage.__init__(self)
        self.topo_id = int(topo_id)

    def length(self):
        return TIOpen.SIZE

    FORMAT = '> H'
    SIZE = struct.calcsize(FORMAT)

    def pack(self):
        return struct.pack(TIOpen.FORMAT, self.topo_id)

    @staticmethod
    def unpack(body):
        t = struct.unpack(TIOpen.FORMAT, body)
        return TIOpen(t[0])

    def __str__(self):
        return 'OPEN: topo_id=%u' % self.topo_id
TI_MESSAGES.append(TIOpen)

class TINodePortHeader(LTMessage):
    def __init__(self, node_name, intf_name):
        LTMessage.__init__(self)
        self.node_name = node_name
        self.intf_name = intf_name

    def length(self):
        return TIInjectPacket.HEADER_SIZE

    HEADER_FORMAT = '> 30s 5s'
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def pack(self):
        return struct.pack(TINodePortHeader.HEADER_FORMAT, self.node_name, self.intf_name)

    @staticmethod
    def unpack_hdr(body):
        t = struct.unpack(TINodePortHeader.HEADER_FORMAT, body[:TINodePortHeader.HEADER_SIZE])
        node_name = strip_null_chars(t[0])
        intf_name = strip_null_chars(t[1])
        return (node_name, intf_name, body[TINodePortHeader.HEADER_SIZE:])

    def __str__(self):
        return '%s:%s' % (self.node_name, self.intf_name)

class TIPacket(TINodePortHeader):
    @staticmethod
    def get_type():
        return 2

    def __init__(self, node_name, intf_name, ethernet_frame):
        TINodePortHeader.__init__(self, node_name, intf_name)
        self.ethernet_frame = ethernet_frame

    def length(self):
        return TINodePortHeader.length(self) + len(self.ethernet_frame)

    def pack(self):
        hdr = TINodePortHeader.pack(self)
        return hdr + self.ethernet_frame

    @staticmethod
    def unpack(body):
        node_name, port_name, body = TINodePortHeader.unpack_hdr(body)
        return TIPacket(node_name, port_name, body)

    def __str__(self):
        return 'PACKET from %s: %s' % (TINodePortHeader.__str__(self), pktstr(self.ethernet_frame))
TI_MESSAGES.append(TIPacket)

class TITap(TINodePortHeader):
    @staticmethod
    def get_type():
        return 3

    def __init__(self, node_name, intf_name, tap, consume):
        """If tap is True, then packets arriving at the specified node on the
        specified interface will be forwarded to this connection.  If consume is
        True, then any tapped packets will not be sent to the topology too."""
        TINodePortHeader.__init__(self, node_name, intf_name)
        self.tap = tap
        self.consume = consume

    def length(self):
        return TINodePortHeader.length(self) + TITap.SIZE

    FORMAT = '> 2b'
    SIZE = struct.calcsize(FORMAT)

    def pack(self):
        hdr = TINodePortHeader.pack(self)
        return hdr + struct.pack(TITap.FORMAT, self.tap, self.consume)

    @staticmethod
    def unpack(body):
        node_name, port_name, body = TINodePortHeader.unpack_hdr(body)
        tap, consume = struct.unpack(TITap.FORMAT, body)
        return TITap(node_name, port_name, tap, consume)

    def __str__(self):
        prefix = 'TAP' if self.tap else 'UNTAP'
        suffix = ' [CONSUME]' if self.tap and self.consume else ''
        return '%s %s%s' % (prefix, TINodePortHeader.__str__(self), suffix)
TI_MESSAGES.append(TITap)

class TIModifyLink(TINodePortHeader):
    @staticmethod
    def get_type():
        return 4

    def __init__(self, node_name, intf_name, enable):
        """If enable is True, then the link attached to the specified node's
        interface will be enabled, otherwise it will be disabled."""
        TINodePortHeader.__init__(self, node_name, intf_name)
        self.enable = enable

    def length(self):
        return TINodePortHeader.length(self) + TIModifyLink.SIZE

    FORMAT = '> b'
    SIZE = struct.calcsize(FORMAT)

    def pack(self):
        hdr = TINodePortHeader.pack(self)
        return hdr + struct.pack(TIModifyLink.FORMAT, self.enable)

    @staticmethod
    def unpack(body):
        node_name, port_name, body = TINodePortHeader.unpack_hdr(body)
        enable = struct.unpack(TIModifyLink.FORMAT, body)[0]
        return TIModifyLink(node_name, port_name, enable)

    def __str__(self):
        prefix = 'EN' if self.enable else 'DIS'
        return '%sABLE link connected to %s' % (prefix, TINodePortHeader.__str__(self))
TI_MESSAGES.append(TIModifyLink)

class TIBanner(LTMessage):
    @staticmethod
    def get_type():
        return 5

    def __init__(self, msg):
        LTMessage.__init__(self)
        self.msg = str(msg)

    def length(self):
        return len(self.msg)

    def pack(self):
        return self.msg

    @staticmethod
    def unpack(body):
        return TIBanner(body)

    def __str__(self):
        return 'ERROR: %s' % self.msg
TI_MESSAGES.append(TIBanner)

TI_PROTOCOL = LTProtocol(TI_MESSAGES, 'H', 'H')

def create_ti_server(port, recv_callback, new_conn_callback, lost_conn_callback, verbose=True):
    """Starts a server which listens for TI clients on the specified port.

    @param port  the port to listen on
    @param recv_callback  the function to call with received message content
                         (takes two arguments: transport, msg)
    @param new_conn_callback   called with one argument (a LTProtocol) when a connection is started
    @param lost_conn_callback  called with one argument (a LTProtocol) when a connection is lost
    @param verbose        whether to print messages when they are sent

    @return returns the new LTTwistedServer
    """
    server = LTTwistedServer(TI_PROTOCOL, recv_callback, new_conn_callback, lost_conn_callback, verbose)
    server.listen(port)
    return server
