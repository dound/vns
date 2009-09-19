"""Defines some simple helper methods for logging."""

import logging
import struct
import traceback
from socket import inet_ntoa

from impacket.ImpactDecoder import EthDecoder

def log_exception(lvl, msg):
    """Like logging.exception(msg) except you may choose what level to log to."""
    logging.log(lvl, msg + '\n' + traceback.format_exc()[:-1])

def addrstr(addr):
    """Returns a pretty-printed address."""
    if len(addr)!= 4:
        return hexstr(addr)
    else:
        return inet_ntoa(addr)

def hexstr(bs):
    """Returns a hexidecimal dump of the specified byte-string."""
    bytes = struct.unpack('> %uB' % len(bs), bs)
    return ''.join(['%0.2X' % byte for byte in bytes])

__decoder = EthDecoder()
def pktstr(pkt):
    """Returns a human-readable dump of the specified packet."""
    ret = '\n' + str(__decoder.decode(pkt))
    return ret.replace('\n', '\n    ')
