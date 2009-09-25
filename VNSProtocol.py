"""Defines the VNS protocol and some associated helper functions."""

from socket import inet_ntoa
import struct

from ltprotocol.ltprotocol import LTMessage, LTProtocol, LTTwistedServer

VNS_DEFAULT_PORT = 12345
VNS_MESSAGES = []
IDSIZE = 32

class VNSOpen(LTMessage):
    @staticmethod
    def get_type():
        return 1

    def __init__(self, topo_id, virtualHostID, UID, pw):
        LTMessage.__init__(self)
        self.topo_id = int(topo_id)
        self.vhost = str(virtualHostID)
        self.user = str(UID)
        self.pw = str(pw)

    def length(self):
        return VNSOpen.SIZE

    FORMAT = '> HH %us %us %us' % (IDSIZE, IDSIZE, IDSIZE)
    SIZE = struct.calcsize(FORMAT)

    def pack(self):
        return struct.pack(VNSOpen.FORMAT, self.topo_id, 0, self.vhost, self.user, self.pw)

    @staticmethod
    def unpack(body):
        t = struct.unpack(VNSOpen.FORMAT, body)
        return VNSOpen(t[0], t[2], t[3], t[4]) # t[1] is pad => ignored

    def __str__(self):
        return 'OPEN: topo_id=%u host=%s user=%s' % (self.topo_id, self.vhost, self.user)
VNS_MESSAGES.append(VNSOpen)

class VNSClose(LTMessage):
    @staticmethod
    def get_type():
        return 2

    def __init__(self, msg):
        LTMessage.__init__(self)
        self.msg = str(msg)

    def length(self):
        return VNSClose.SIZE

    FORMAT = '> 256s'
    SIZE = struct.calcsize(FORMAT)

    def pack(self):
        return struct.pack(VNSClose.FORMAT, self.msg)

    @staticmethod
    def unpack(body):
        t = struct.unpack(VNSClose.FORMAT, body)
        return VNSClose(t[0])

    def __str__(self):
        return 'CLOSE: %s' % self.msg
VNS_MESSAGES.append(VNSClose)

class VNSPacket(LTMessage):
    @staticmethod
    def get_type():
        return 4

    def __init__(self, intf_name, ethernet_frame):
        LTMessage.__init__(self)
        self.intf_name = str(intf_name)
        self.ethernet_frame = str(ethernet_frame)

    def length(self):
        return VNSPacket.HEADER_SIZE + len(self.ethernet_frame)

    HEADER_FORMAT = '> 16s'
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def pack(self):
        return struct.pack(VNSPacket.HEADER_FORMAT, self.intf_name) + self.ethernet_frame

    @staticmethod
    def unpack(body):
        t = struct.unpack(VNSPacket.HEADER_FORMAT, body[:VNSPacket.HEADER_SIZE])
        return VNSPacket(t[0], body[VNSPacket.HEADER_SIZE:])

    def __str__(self):
        return 'PACKET: %uB on %s' % (len(self.ethernet_frame), self.intf_name)
VNS_MESSAGES.append(VNSPacket)

class VNSProtocolException(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg

class VNSInterface:
    def __init__(self, name, mac, ip, mask):
        self.name = str(name)
        self.mac = str(mac)
        self.ip = str(ip)
        self.mask = str(mask)

        if len(mac) != 6:
            raise VNSProtocolException('MAC address must be 6B')

        if len(ip) != 4:
            raise VNSProtocolException('IP address must be 4B')

        if len(mask) != 4:
            raise VNSProtocolException('IP address mask must be 4B')

    HWINTERFACE = 1  # string
    HWSPEED = 2      # uint32
    HWSUBNET = 4     # uint32
    HWETHER = 32     # string
    HWETHIP = 64     # uint32
    HWMASK = 128     # uint32

    FORMAT = '> I32s II28s I32s I4s28s II28s I4s28s'
    SIZE = struct.calcsize(FORMAT)

    def pack(self):
        return struct.pack(VNSInterface.FORMAT,
                           VNSInterface.HWINTERFACE, self.name,
                           VNSInterface.HWSPEED, 0, '',
                           VNSInterface.HWETHER, self.mac,
                           VNSInterface.HWETHIP, self.ip, '',
                           VNSInterface.HWSUBNET, 0, '',
                           VNSInterface.HWMASK, self.mask, '')

    def __str__(self):
        fmt = '%s: mac=%s ip=%s mask=%s'
        return fmt % (self.name, self.mac, inet_ntoa(self.ip), inet_ntoa(self.mask))

class VNSBanner(LTMessage):
    @staticmethod
    def get_type():
        return 8

    def __init__(self, msg):
        LTMessage.__init__(self)
        self.msg = str(msg)

    def length(self):
        return VNSBanner.SIZE

    FORMAT = '> 256s'
    SIZE = struct.calcsize(FORMAT)

    def pack(self):
        return struct.pack(VNSBanner.FORMAT, self.msg)

    @staticmethod
    def unpack(body):
        t = struct.unpack(VNSBanner.FORMAT, body)
        return VNSBanner(t[0])

    def __str__(self):
        return 'BANNER: %s' % self.msg
VNS_MESSAGES.append(VNSBanner)

class VNSHardwareInfo(LTMessage):
    @staticmethod
    def get_type():
        return 16

    def __init__(self, interfaces):
        LTMessage.__init__(self)
        self.interfaces = interfaces

    def length(self):
        return len(self.interfaces) * VNSInterface.SIZE

    def pack(self):
        return ''.join([intf.pack() for intf in self.interfaces])

    def __str__(self):
        return 'Hardware Info: %s' % ' || '.join([str(intf) for intf in self.interfaces])
VNS_MESSAGES.append(VNSHardwareInfo)

VNS_PROTOCOL = LTProtocol(VNS_MESSAGES, 'I', 'I')

def create_vns_server(port, recv_callback, lost_conn_callback, verbose=True):
    """Starts a server which listens for VNS clients on the specified port.

    @param port  the port to listen on
    @param recv_callback  the function to call with received message content
                         (takes two arguments: transport, msg)
    @param lost_conn_callback  called with one argument (a LTProtocol) when a connection is lost
    @param verbose        whether to print messages when they are sent

    @return returns the new LTTwistedServer
    """
    server = LTTwistedServer(VNS_PROTOCOL, recv_callback, None, lost_conn_callback, verbose)
    server.listen(port)
    return server
