"""A lightweight HTTP server based on TCPStack."""
import logging
import re
import socket
import sys

from LoggingHelper import addrstr
from LoggingHelper import portstr
from twisted.internet import reactor

from TCPStack import TCPServer

class HTTPServer(TCPServer):
    """Implements a basic HTTP Server which handles raw TCP packets passed to it."""
    def __init__(self, port, serve_from, max_active_conns=25, default_page='index.html'):
        """Constructs an HTTP server listening on the specified port and serving
        files from the specified folder 'serve_from'."""
        TCPServer.__init__(self, port, max_active_conns)
        self.serve_from = serve_from
        self.default_page = default_page

    RE_GET = re.compile('GET (.*) HTTP/\d+.\d+\r\n((.|\n)+\r\n)?\r\n')
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

    def get_path_being_served(self):
        """Returns the path this server is serving files from."""
        return self.serve_from

    def handle_tcp(self, pkt):
        # take care of the usual TCP stuff
        conn = TCPServer.handle_tcp(self, pkt)
        if not conn or conn.closed:
            return conn

        # check to see if we've received a complete HTTP request
        url_requested = self.extract_http_get_request(conn)
        if url_requested:
            logging.debug('A URL has been requested: ' + url_requested)
            conn.add_data_to_send(self.__make_response(url_requested, pkt))
            logging.debug('The requested URL has been sent; closing the connection')
            conn.close()
        return conn

    @staticmethod
    def __make_response_header(ok, is_html=True, gen_body_if_404=True):
        """Generates the header of an HTTP response.  This includes the status
        line and content-type.  If a 404 status line is generated, then a
        basic 404 page body will also be generated."""
        code='200 OK' if ok else '404 Not Found'
        ctype='text/html' if is_html else 'application/octet-stream'
        header = 'HTTP/1.0 %s\r\nContent-Type: %s;\r\n\r\n' % (code, ctype)
        if not ok and gen_body_if_404:
            header += '<html><body><h1>404: Page Not Found</h1></body></html>'
        return header

    @staticmethod
    def __make_response_dynamic_body(body, pkt):
        """Replaces tags in a given response body with the proper values from
        the request packet. This is used in order to see what request ip and
        port the HTTPServer sees (useful for testing NAT)."""

        body = body.replace('%SRC_PORT%', portstr(pkt.tcp_src_port))
        body = body.replace('%SRC_IP%', addrstr(pkt.ip_src))
        return body

    ALLOWED_CHARS = r'[-A-Za-z0-9_/]*'
    RE_OK_URL = re.compile(r'^%s([.]%s)?$' % (ALLOWED_CHARS, ALLOWED_CHARS))
    RE_HTML = re.compile('^[.]html?([?].*)?$')
    def __make_response(self, url, pkt):
        """Verifies that the URL requested is legitimate (alphanumeric, dash,
        underscore, and forward slash characters are permitted only).  A single
        period is also permitted (to separate a file name from an extension)."""
        if url == '/':
            url = self.default_page

        match = HTTPServer.RE_OK_URL.match(url)
        if match:
            try:
                f = open(self.serve_from + '/' + url, 'rb')
                body = f.read()
                f.close()

                if url.endswith('.dyn'):
                    body = HTTPServer.__make_response_dynamic_body(body, pkt)

                ext_and_trailer = match.group(1)
                is_html = url.endswith('.html') or url.endswith('.dyn')
                header = HTTPServer.__make_response_header(True, is_html)
                return header + body
            except IOError as e:
                logging.debug('unable to find requested file "%s": %s' % (url, e))
        return HTTPServer.__make_response_header(False)

def test():
    """Sniffs TCP packets arriving on port 80 and manually handles them with an
    HTTPServer object which is serving the given path.  For this test to work,
    your OS will need to silently drop or ignore TCP packets to port 80 (e.g.,
    temporarily add a DENY rule for TCP port 80 to your firewall).  If you do
    not do this, then your OS will probably respond with TCP resets at the same
    time as the manual TCP stack is trying to reply with its own response."""
    from pcapy import open_live, PcapError
    from ProtocolHelper import Packet
    from LoggingHelper import pktstr
    import errno

    dev = sys.argv[1] if len(sys.argv) > 1 else 'eth0'
    path_to_serve = sys.argv[2] if len(sys.argv) > 2 else './htdocs'

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
        logging.debug('--------------------------------------------------')
        logging.debug('--------------------------------------------------')
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

    def run_pcap():
        """Start listening for packets coming in from the outside world."""
        MAX_LEN      = 1514    # max size of packet to capture
        PROMISCUOUS  = 1       # promiscuous mode?
        READ_TIMEOUT = 100     # in milliseconds
        MAX_PKTS     = -1      # number of packets to capture; -1 => no limit
        PCAP_FILTER  = 'tcp dst port 80'

        # the method which will be called when a packet is captured
        def ph(_, data):
            # thread safety: call from the main twisted event loop
            reactor.callFromThread(handle_packet_from_outside, data)

        # start the packet capture
        try:
            p = open_live(dev, MAX_LEN, PROMISCUOUS, READ_TIMEOUT)
        except PcapError:
            print 'failed to start pcap (interface not up or not root?)'
            sys.exit(-1)

        p.setfilter(PCAP_FILTER)
        logging.debug("Listening on %s: net=%s, mask=%s, filter=%s" % (dev, p.getnet(), p.getmask(), PCAP_FILTER))
        p.loop(MAX_PKTS, ph)

    reactor.callInThread(run_pcap)
    reactor.run()

if __name__ == '__main__':
    def bye():
        import os
        os._exit(0)

    reactor.addSystemEventTrigger("before", "shutdown", bye)
    logging.basicConfig(level=logging.DEBUG, format='%(levelname)-8s %(module)s:%(funcName)s:%(lineno)d  %(message)s')

    try:
        test()
    except KeyboardInterrupt:
        sys.exit(0)
