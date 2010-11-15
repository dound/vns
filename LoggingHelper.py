"""Defines some simple helper methods for logging."""

import logging
from socket import inet_ntoa
import struct
import time
import traceback

from impacket.ImpactDecoder import EthDecoder
from impacket.ImpactPacket import ImpactPacketException

PCAP_SNAPLEN = 1514

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

def portstr(nbo_port):
  """Returns a host byte order string for the given network byte order port."""
  return str(struct.unpack('>H', nbo_port)[0])

def split_then_join(s, chunk_sz, join_str):
    """Splits s into chunk_sz chunks and then joins those chunks using join_str."""
    return join_str.join([s[i*chunk_sz:(i+1)*chunk_sz] for i in range((len(s)-1)/chunk_sz+1)])

def hexstr(bs, add_spacing=True):
    """Returns a hexidecimal dump of the specified byte-string."""
    bytes = struct.unpack('> %uB' % len(bs), bs)
    hs = ''.join(['%0.2X' % byte for byte in bytes])
    if not add_spacing:
        return hs
    pairs = split_then_join(hs, 2, ' ')
    return split_then_join(pairs, 24, '   ')

__last_pkt = None
__decoder = EthDecoder()
def pktstr(pkt, noop=True):
    """Returns a human-readable dump of the specified packet."""
    if noop:
        return '' # PERFORMANCE: remove this to get packet-level print-outs (but it has a huge impact on performance: >2x)
    global __last_pkt
    if pkt is __last_pkt:
        return 'same as last'
    else:
        __last_pkt = pkt

    try:
        ret = '\n' + str(__decoder.decode(pkt))
        return ret.replace('\n', '\n    ')
    except ImpactPacketException as e:
        return 'packet=%s (decoding failed: %s)' % (hexstr(pkt), str(e))

def pcap_write_header(fp):
    magic = 0xa1b2c3d4
    version_major = 2
    version_minor = 4
    this_zone = 0
    sigfigs = 0
    snaplen = PCAP_SNAPLEN
    linktype = 1  # ethernet
    hdr = struct.pack('>I 2H 4I', magic, version_major, version_minor, this_zone, sigfigs, snaplen, linktype)
    fp.write(hdr)

def pcap_write_packet(fp, pkt):
    now = time.time()
    sec = int(now)
    microsec = int(1000000 * (now - sec))
    sz_actual = len(pkt)
    sz_written = min(PCAP_SNAPLEN, sz_actual)
    hdr = struct.pack('> 4I', sec, microsec, sz_written, sz_actual)
    fp.write(hdr)
    fp.write(pkt[:sz_written])
