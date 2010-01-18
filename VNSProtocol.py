"""Defines the VNS protocol and some associated helper functions."""

import re
from socket import inet_aton, inet_ntoa
import struct

from ltprotocol.ltprotocol import LTMessage, LTProtocol, LTTwistedServer

VNS_DEFAULT_PORT = 3250
VNS_MESSAGES = []
IDSIZE = 32

__clean_re = re.compile(r'\x00*')
def strip_null_chars(s):
    """Remove null characters from a string."""
    return __clean_re.sub('', s)

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
        t = struct.unpack(VNSOpen.FORMAT, body) # t[1] is pad => ignored
        vhost = strip_null_chars(t[2])
        user = strip_null_chars(t[3])
        pw = strip_null_chars(t[4])
        return VNSOpen(t[0], vhost, user, pw)

    def __str__(self):
        return 'OPEN: topo_id=%u host=%s user=%s' % (self.topo_id, self.vhost, self.user)
VNS_MESSAGES.append(VNSOpen)

class VNSClose(LTMessage):
    @staticmethod
    def get_type():
        return 2

    @staticmethod
    def get_banners_and_close(msg):
        """Split msg up into the minimum number of VNSBanner messages and VNSClose it will fit in."""
        msgs = []
        n = len(msg)/255 + 1
        for i in range(n):
            if i+1 < n:
                msgs.append(VNSBanner(msg[i*255:(i+1)*255]))
            else:
                msgs.append(VNSClose(msg[i*255:(i+1)*255]))
        return msgs

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
        return VNSClose(strip_null_chars(t[0]))

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
        intf_name = strip_null_chars(t[0])
        return VNSPacket(intf_name, body[VNSPacket.HEADER_SIZE:])

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

    @staticmethod
    def get_banners(msg):
        """Split msg up into the minimum number of VNSBanner messages it will fit in."""
        msgs = []
        n = len(msg)/255 + 1
        for i in range(n):
            msgs.append(VNSBanner(msg[i*255:(i+1)*255]))
        return msgs

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
        return VNSBanner(strip_null_chars(t[0]))

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

class VNSRtable(LTMessage):
    @staticmethod
    def get_type():
        return 32

    def __init__(self, virtualHostID, rtable):
        LTMessage.__init__(self)
        self.vrhost = virtualHostID
        self.rtable = str(rtable)

    def length(self):
        return VNSRtable.HEADER_SIZE + len(self.rtable)

    HEADER_FORMAT = '> %us' % IDSIZE
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def pack(self):
        return struct.pack(VNSRtable.HEADER_FORMAT, self.vrhost) + self.rtable

    @staticmethod
    def unpack(body):
        vrhost = strip_null_chars(body[:IDSIZE])
        return VNSRtable(vrhost, body[IDSIZE:])

    def __str__(self):
        return 'RTABLE: node=%s:\n%s' % (self.vrhost, self.rtable)
VNS_MESSAGES.append(VNSRtable)

class VNSOpenTemplate(LTMessage):
    @staticmethod
    def get_type():
        return 64

    NO_SRC_FILTERS = [('0.0.0.0', 0)]

    def __init__(self, template_name, virtualHostID, src_filters):
        """src_filters should be a list of (ip, mask) tuples (an empty list is
        interpreted as having no source filters).  The IP addresses should be
        strings and the masks should be an integer (specifying the number of
        bits set in the mask)."""
        LTMessage.__init__(self)
        self.template_name = template_name
        self.vrhost = virtualHostID
        self.__set_src_filters(src_filters)

    def length(self):
        return VNSOpenTemplate.HEADER_SIZE + 30 + 5*len(self.src_filters)

    HEADER_FORMAT = '> 30s %us' % IDSIZE
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)

    def get_src_filters(self):
        """Returns a list of source filters -- always has at least one entry.
        Each element is a 2-tuple of an IP address (string form) and an integer
        indicating the number of masked bits."""
        return self.src_filters

    def __set_src_filters(self, src_filters):
        if src_filters:
            self.src_filters = src_filters
        else:
            self.src_filters = VNSOpenTemplate.NO_SRC_FILTERS

    def pack(self):
        body = ''.join((inet_aton(ip) + struct.pack('>B', mask)) for ip,mask in self.src_filters)
        return struct.pack(VNSOpenTemplate.HEADER_FORMAT, self.template_name, self.vrhost) + body

    @staticmethod
    def unpack(body):
        t = struct.unpack(VNSOpenTemplate.HEADER_FORMAT, body[:VNSOpenTemplate.HEADER_SIZE])
        template_name = strip_null_chars(t[0])
        vrhost = strip_null_chars(t[1])
        src_filters = []
        sf_bytes = body[VNSOpenTemplate.HEADER_SIZE:]
        for i in range(len(sf_bytes) / 5):
            ip = inet_ntoa(sf_bytes[i*5:i*5+4])
            mask = struct.unpack('>B', sf_bytes[i*5+4])[0]
            if mask < 0 or mask > 32:
                raise VNSProtocolException('mask must be between 0 and 32 but it was %d' % mask)
            src_filters.append((ip, mask))
        return VNSOpenTemplate(template_name, vrhost, src_filters)

    def __str__(self):
        str_filters = ','.join('%s/%d' % (ip, mask) for ip,mask in self.src_filters)
        return 'OPEN_TEMPLATE: %s for node=%s with filters=%s' % (self.template_name, self.vrhost, str_filters)
VNS_MESSAGES.append(VNSOpenTemplate)

class VNSAuthRequest(LTMessage):
    @staticmethod
    def get_type():
        return 128

    def __init__(self, salt):
        LTMessage.__init__(self)
        self.salt = salt

    def length(self):
        return len(self.salt)

    def pack(self):
        return self.salt

    @staticmethod
    def unpack(body):
        return VNSAuthRequest(body)

    def __str__(self):
        return 'AUTH_REQUEST: ' + ' salt length=%uB' % len(self.salt)
VNS_MESSAGES.append(VNSAuthRequest)

class VNSAuthReply(LTMessage):
    @staticmethod
    def get_type():
        return 256

    def __init__(self, username, sha1_of_salted_pw):
        LTMessage.__init__(self)
        self.username = username
        self.ssp = sha1_of_salted_pw

    def length(self):
        return len(self.username) + len(self.ssp)

    def pack(self):
        return struct.pack('>I', len(self.username)) + self.username + self.ssp

    @staticmethod
    def unpack(body):
        username_len = struct.unpack('>I', body[:4])[0]
        body = body[4:]
        username = body[:username_len]
        ssp = body[username_len:]
        return VNSAuthReply(username, ssp)

    def __str__(self):
        return 'AUTH_REPLY: ' + ' username=' + self.username
VNS_MESSAGES.append(VNSAuthReply)

class VNSAuthStatus(LTMessage):
    @staticmethod
    def get_type():
        return 512

    def __init__(self, auth_ok, msg):
        LTMessage.__init__(self)
        self.auth_ok = bool(auth_ok)
        self.msg = msg

    def length(self):
        return 1 + len(self.msg)

    def pack(self):
        return struct.pack('>B', self.auth_ok) + self.msg

    @staticmethod
    def unpack(body):
        auth_ok = struct.unpack('>B', body[:1])[0]
        msg = body[1:]
        return VNSAuthStatus(auth_ok, msg)

    def __str__(self):
        return 'AUTH_STATUS: ' + ' auth_ok=%s msg=%s' % (str(self.auth_ok), self.msg)
VNS_MESSAGES.append(VNSAuthStatus)

VNS_PROTOCOL = LTProtocol(VNS_MESSAGES, 'I', 'I')

def create_vns_server(port, recv_callback, new_conn_callback, lost_conn_callback, verbose=True):
    """Starts a server which listens for VNS clients on the specified port.

    @param port  the port to listen on
    @param recv_callback  the function to call with received message content
                         (takes two arguments: transport, msg)
    @param new_conn_callback   called with one argument (a LTProtocol) when a connection is started
    @param lost_conn_callback  called with one argument (a LTProtocol) when a connection is lost
    @param verbose        whether to print messages when they are sent

    @return returns the new LTTwistedServer
    """
    server = LTTwistedServer(VNS_PROTOCOL, recv_callback, new_conn_callback, lost_conn_callback, verbose)
    server.listen(port)
    return server
