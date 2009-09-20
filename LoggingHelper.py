"""Defines some simple helper methods for logging."""

import logging
import struct
import traceback
from socket import inet_ntoa

from impacket.ImpactDecoder import EthDecoder
from impacket.ImpactPacket import ImpactPacketException

def log_exception(lvl, msg):
    """Like logging.exception(msg) except you may choose what level to log to."""
    logging.log(lvl, msg + '\n' + traceback.format_exc()[:-1])

def addrstr(addr):
    """Returns a pretty-printed address."""
    sz = len(addr)
    if sz == 4: # IP
        return inet_ntoa(addr)
    elif sz == 6: # MAC
        return hexstr(addr)
    else:
        logging.warning('unexpected address length: %d' % sz)
        return hexstr(addr)

def hexstr(bs):
    """Returns a hexidecimal dump of the specified byte-string."""
    bytes = struct.unpack('> %uB' % len(bs), bs)
    return ''.join(['%0.2X' % byte for byte in bytes])

__last_pkt = None
__decoder = EthDecoder()
def pktstr(pkt):
    """Returns a human-readable dump of the specified packet."""
    global __last_pkt
    if pkt is __last_pkt:
        return 'same as last'
    else:
        __last_pkt = pkt

    try:
        ret = '\n' + str(__decoder.decode(pkt))
    except ImpactPacketException:
        log_exception(logging.WARN, 'packet decoding failed')
        ret = 'packet=??? (decoding failed)'

    return ret.replace('\n', '\n    ')
