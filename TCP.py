"""A very, very simple TCP stack."""
from SocketServer import TCPServer
import logging
import random
import re
import struct
import sys
import time

from twisted.internet import reactor

ASSUMED_RTT_SEC = 2.000
CHUNK_SIZE = 1460
MAX_DATA_ALLOWED = 10000

def make_tcp_packet(src_port, dst_port, seq=0, ack=0, window=5096, data='',
                    is_fin=False, is_rst=False, is_syn=False):
    flags = 0x10 # ACK
    if is_fin:
        flags |= 0x01
    if is_syn:
        flags |= 0x02
    if is_rst:
        flags |= 0x04

    return (src_port + dst_port + struct.pack('> 2I', seq, ack) + '\x50' + \
           struct.pack('>B H', flags, window) + '\x00\x00\x00\x00', data)

class TCPSegment():
    """Describes a contiguous chunk of data in a TCP stream."""
    def __init__(self, seq, data):
        self.seq = seq               # sequence # of the first byte in this segment
        self.data = data             # data in this segment
        self.next = seq + len(data)  # first sequence # of the next data byte
        if not data:
            raise Exception('segments must contain at least 1B of data')

    def combine(self, s2):
        """Combine this segment with a s2 which comes no earlier than this
        segment starts.  If they do not overlap or meet, False is returned."""
        assert(self.__cmp__(s2) <= 0) # s2 must not start earlier

        if self.next < s2.seq:
            return False # no overlap: s2 is later than us

        if self.next >= s2.next:
            return True # self completely subsumes s2

        # combine the two segments
        offset = self.next - s2.seq
        new_data = self.data + s2.data[offset:] # union of the two

        self.data = new_data
        self.next = s2.next
        return True

    def __cmp__(self, x):
        return cmp(self.seq, x.seq)

class TCPConnection():
    def __init__(self, syn_seq, my_ip, my_port, other_ip, other_port):
        self.my_ip = my_ip
        self.my_port = my_port
        self.other_ip = other_ip
        self.other_port = other_port

        self.segments = []
        self.next_seq_needed = syn_seq + 1
        self.need_to_send_ack = False
        self.received_fin = False

        self.window = 0
        self.data_to_send = ''
        self.first_unacked_seq = random.randint(0, 0x8FFFFFFF)
        self.my_syn_acked = False
        self.my_fin_acked = False
        self.closed = False
        self.next_resend = 0

    def add_segment(self, segment):
        """Puts together a newly received segment."""
        self.__add_segment(segment)
        if len(self.segments) > 0 and self.segments[0].next > self.next_seq_needed:
            self.next_seq_needed = self.segments[0].next
            self.need_to_send_ack = True # we just got new data

    def __add_segment(self, segment):
        combined_index = None
        for i in range(len(self.segments)):
            if self.segments[i].combine(segment):
                combined_index = i
                break

        if not combined_index:
            self.segments.append(segment)
            logging.debug('appended the new segment to the end of our current segments list')
            return
        else:
            logging.debug('merging the new segment into segment %d' % i)

        i = combined_index
        new_segment = self.segments[i]
        while i < len(self.segments)-1:
            if new_segment.combine(self.segments[i+1]):
                self.segments.pop(i+1)
            else:
                break

    def got_fin(self, seq):
        """Indicates that a FIN has been received from the other side."""
        self.received_fin = True
        self.next_seq_needed = seq + 1
        self.need_to_send_ack = True
        self.next_resend = 0  # send now

    def get_ack_num(self):
        return self.next_seq_needed

    def set_ack(self, ack):
        """Handles receipt of an ACK."""
        diff = ack - self.first_unacked_seq
        if diff > 0:
            if not self.my_syn_acked:
                diff = diff - 1
                self.my_syn_acked = True

            if diff > len(self.data_to_send):
                self.my_fin_acked = True

            self.data_to_send = self.data_to_send[diff:]
            self.first_unacked_seq = ack

    def get_packets_to_send(self):
        """Returns a list of packets which should be sent now."""
        ret = []

        # is it time to send data?
        now = time.time()
        if now < self.next_resend:
            logging.debug('not time to send any packets yet (now=%d next=%d)' % (now, self.next_resend))
            return ret

        # do we have something to send?
        if not self.my_syn_acked:
            logging.debug('Adding my SYN packet to the outgoing queue')
            ret.append(make_tcp_packet(self.my_port, self.other_port,
                                       seq=self.first_unacked_seq,
                                       ack=self.get_ack_num(),
                                       data='',
                                       is_syn=True))

        sz = len(self.data_to_send)
        base_offset = self.first_unacked_seq + (0 if self.my_syn_acked else 1)
        if self.data_to_send:
            for i in range(1+(sz-1)/CHUNK_SIZE):
                start = base_offset + i*CHUNK_SIZE
                end = min(sz, (i+1)*CHUNK_SIZE)
                logging.debug('Adding data bytes from %d to %d to the outgoing queue' % (start, end-1))
                ret.append(make_tcp_packet(self.my_port, self.other_port,
                                           seq=start,
                                           ack=self.get_ack_num(),
                                           data=self.data_to_send[i*CHUNK_SIZE:end]))

        if self.closed and not self.my_fin_acked:
            logging.debug('Adding my FIN packet to the outgoing queue')
            ret.append(make_tcp_packet(self.my_port, self.other_port,
                                       seq=base_offset + sz,
                                       ack=self.get_ack_num(),
                                       data='',
                                       is_fin=True))

        if not ret and self.need_to_send_ack:
            logging.debug('Adding a pure ACK to the outgoing queue (nothing to piggyback on)')
            ret.append(make_tcp_packet(self.my_port, self.other_port,
                                       seq=self.get_ack_num(),
                                       ack=self.next_seq_needed,
                                       data=''))

        if ret:
            self.next_resend = now + ASSUMED_RTT_SEC
            self.need_to_send_ack = False
        return ret

    def add_data_to_send(self, data):
        if not self.closed:
            self.data_to_send += data
            self.next_resend = 0  # send now
        else:
            raise Exception('cannot send data on a closed socket')

    def close(self):
        self.closed = True

    def is_all_done(self):
        """True if my fin has been acked."""
        return self.my_fin_acked

    def has_ready_data(self):
        """Returns True if data has been received and there are no gaps in it."""
        logging.debug('# segments = %d' % len(self.segments))
        return len(self.segments) == 1

    def get_data(self):
        """Returns the data received so far (up to the first gap, if any)."""
        if self.segments:
            return self.segments[0].data
        else:
            return ''

class TCPServer():
    """Implements a basic TCP Server which handles raw TCP packets passed to it."""
    # Pass this value to the constructor and the TCPServer will accept connections on any port.
    ANY_PORT = 0

    def __init__(self, port):
        """port is the port the TCPServer should listen for SYN packets on."""
        assert(port>=0 and port<65536, "Port must be between 0 and 65536 (exclusive) or TCPServer.ANY_PORT")
        self.connections = {}
        self.listening_port_nbo = struct.pack('>H', port)

    def get_port_nbo(self):
        """Returns the 2-byte NBO representation of the port being listened on."""
        return self.listening_port_nbo

    def handle_tcp(self, pkt):
        """Processes pkt as if it was just received.  pkt should be a valid TCP
        packet.  Returns the TCPConnection pkt is associated with, if any."""
        assert(pkt.is_tcp() and pkt.is_valid_tcp(), "TCPServer.handle_tcp expects a valid TCP packet as input")

        # ignore TCP packets not to us
        if self.listening_port_nbo != '\x00\x00' and pkt.tcp_dst_port != self.listening_port_nbo:
            logging.debug('ignoring TCP packet to a port we are not listening on')
            return None

        # extract some basic info
        seq, ack, _, window = struct.unpack('>2I 2H', pkt.tcp[4:16])

        # get the connection associated with the client's socket, if any
        socket_client = (pkt.ip_src, pkt.tcp_src_port)
        socket_server = (pkt.ip_dst, pkt.tcp_dst_port)
        socket_pair = (socket_client, socket_server)
        conn = self.connections.get(socket_pair)
        if not conn:
            logging.debug('received TCP packet from a new socket pair: %s' % str(socket_pair))
            # there is no connection for this socket pair -- did we get a SYN?
            if pkt.is_tcp_syn():
                conn = TCPConnection(seq, pkt.ip_dst, pkt.tcp_dst_port, pkt.ip_src, pkt.tcp_src_port)
                self.connections[socket_pair] = conn
                logging.debug('received TCP SYN packet -- new connection created: %s' % conn)
            else:
                logging.debug('ignoring TCP packet without SYN for socket pair with no existing connection')
                return None # this tcp fragment is not part of an active session: ignore it

        # pull out the data
        if len(pkt.tcp_data):
            logging.debug('Adding segment for %d bytes received' % len(pkt.tcp_data))
            conn.add_segment(TCPSegment(seq, pkt.tcp_data))

        if pkt.is_tcp_fin():
            conn.got_fin(seq)

        # remember window and latest ACK
        conn.window = window
        if pkt.is_tcp_ack():
            conn.set_ack(ack)
        return conn

class HTTPServer(TCPServer):
    """Implements a basic HTTP Server which handles raw TCP packets passed to it."""
    def __init__(self, port, serve_from, default_page='index.html'):
        """Constructs an HTTP server listening on the specified port and serving
        files from the specified folder 'serve_from'."""
        TCPServer.__init__(self, port)
        self.serve_from = serve_from
        self.default_page = default_page

    RE_GET = re.compile('GET (.*) HTTP/1.1\r\n((.|\n)+\r\n)?\r\n')
    def extract_http_get_request(self, conn):
        """If the data received is an HTTP GET request, then the requested URL
        is returned.  Otherwise, None is returned."""
        if conn.has_ready_data():
            data = conn.get_data()
            m = HTTPServer.RE_GET.match(data)
            if m:
                return m.group(1)
            else:
                logging.debug('data does not match GET request (%s...)' % data[0:20])
        return None

    def handle_tcp(self, pkt):
        # take care of the usual TCP stuff
        conn = TCPServer.handle_tcp(self, pkt)
        if not conn or conn.closed:
            return conn

        # check to see if we've received a complete HTTP request
        url_requested = self.extract_http_get_request(conn)
        if url_requested:
            logging.debug('A URL has been requested: ' + url_requested)
            conn.add_data_to_send(self.__make_response(url_requested))
            logging.debug('The requested URL has been sent; closing the connection')
            conn.close()
        return conn

    @staticmethod
    def __make_response_header(ok, is_html=True, gen_body_if_404=True):
        """Generates the header of an HTTP response.  This includes the status
        line and content-type.  If a 404 status line is generated, then a
        basic 404 page body will also be generated."""
        code='200 OK' if ok else '404 Not Found'
        type='text/html' if is_html else 'application/octet-stream'
        header = 'HTTP/1.0 %s\r\nContent-Type: %s;\r\n\r\n' % (code, type)
        if not ok and gen_body_if_404:
            return header + '<html><body><h1>404: Page Not Found</h1></body></html>'

    ALLOWED_CHARS = r'[-A-Za-z0-9_/]*'
    RE_OK_URL = re.compile(r'^%s([.]%s)?$' % (ALLOWED_CHARS, ALLOWED_CHARS))
    RE_HTML = re.compile('^[.]html?([?].*)?$')
    def __make_response(self, url):
        """Verifies that the URL requested is legitimate (alphanumeric, dash,
        underscore, and forward slash characters are permitted only).  A single
        period is also permitted (to separate a file name from an extension)."""
        if url == '/':
            url = self.default_page

        match = HTTPServer.RE_OK_URL.match(url)
        if match:
            try:
                f = open(self.serve_from + '/' + url)
                body = f.read()
                f.close()

                ext_and_trailer = match.group(1)
                is_html = HTTPServer.RE_HTML.search(ext_and_trailer)
                header = HTTPServer.__make_response_header(True, is_html)
                header = 'HTTP/1.0 200 OK\r\nContent-Type: %s;\r\n\r\n' % type
                return header + body
            except IOError as e:
                logging.debug('unable to find requested file "%s": %s' % (url, e))
        return HTTPServer.__make_response_header(False)

def test(dev, path_to_serve):
    from pcapy import open_live, PcapError
    from ProtocolHelper import Packet
    from LoggingHelper import pktstr
    import errno
    import socket

    def start_raw_socket(dev):
        """Starts a socket for sending raw Ethernet frames."""
        try:
            raw_socket = socket.socket(socket.PF_PACKET, socket.SOCK_RAW)
            raw_socket.bind((dev, 0x9999))
            return raw_socket
        except socket.error as e:
            if e.errno == errno.EPERM:
                extra = ' (did you forget to run me with root?)'
            else:
                extra = ''
            logging.exception('failed to open raw socket' + extra)
            sys.exit(-1)

    port = 80
    server = HTTPServer(port, path_to_serve)
    logging.debug('Created HTTPServer object listening on port %d' % port)
    raw_socket = start_raw_socket(dev)

    def handle_packet_from_outside(data):
        logging.debug('got packet: %s' % pktstr(data))
        pkt = Packet(data)

        if pkt.is_tcp() and pkt.is_valid_tcp():
            logging.debug('passing on tcp packet ...')
            tcp_conn = server.handle_tcp(pkt)
            if tcp_conn:
                tcp_pts = tcp_conn.get_packets_to_send()
                if tcp_pts:
                    for tcp, data in tcp_pts:
                        eth = pkt.get_reversed_eth()
                        ip = pkt.get_reversed_ip(new_ttl=64, new_tlen=pkt.ip_hlen+len(tcp)+len(data))
                        p = eth + ip + Packet.cksum_tcp_hdr(ip, tcp, data) + data
                        logging.debug('sending packet: %s' % pktstr(p))
                        try:
                            raw_socket.send(p)
                        except socket.error:
                            logging.exception('failed to send packet')
                            sys.exit(-1)
                else:
                    logging.debug('no packets to send back')

    def run_pcap(dev):
        """Start listening for packets coming in from the outside world."""
        MAX_LEN      = 1514    # max size of packet to capture
        PROMISCUOUS  = 1       # promiscuous mode?
        READ_TIMEOUT = 100     # in milliseconds
        MAX_PKTS     = -1      # number of packets to capture; -1 => no limit
        PCAP_FILTER  = 'tcp port 80'

        # the method which will be called when a packet is captured
        def ph(_, data):
            # thread safety: call from the main twisted event loop
            handle_packet_from_outside(data)

        # start the packet capture
        try:
            p = open_live(dev, MAX_LEN, PROMISCUOUS, READ_TIMEOUT)
        except PcapError:
            print 'failed to start pcap (interface not up or not root?)'
            sys.exit(-1)

        p.setfilter(PCAP_FILTER)
        logging.debug("Listening on %s: net=%s, mask=%s, filter=%s" % (dev, p.getnet(), p.getmask(), PCAP_FILTER))
        p.loop(MAX_PKTS, ph)

    reactor.callInThread(run_pcap, DEV)
    reactor.run()

if __name__ == '__main__':
    def bye():
        import os
        os._exit(0)

    reactor.addSystemEventTrigger("before", "shutdown", bye)
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)-8s %(module)s:%(funcName)s:%(lineno)d  %(message)s')

    try:
        test('eth0', './htdocs')
    except KeyboardInterrupt:
        sys.exit(0)
