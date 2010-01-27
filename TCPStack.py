"""A lightweight TCP stack.  Includes a TCP server which uses this stack."""
import logging
import random
import socket
import struct
import time

from twisted.internet import reactor

def make_tcp_packet(src_port, dst_port, seq=0, ack=0, window=5096, data='',
                    is_fin=False, is_rst=False, is_syn=False, is_ack=True):
    """Creates a TCP header with no options and with the checksum zeroed."""
    flags = 0x00
    if is_fin:
        flags |= 0x01
    if is_syn:
        flags |= 0x02
    if is_rst:
        flags |= 0x04
    if is_ack:
        flags |= 0x10
    return (src_port + dst_port + struct.pack('> 2I', seq, ack) + '\x50' + \
           struct.pack('>B H', flags, window) + '\x00\x00\x00\x00', data)

def add_fin_to_tcp_packet(p):
    """Add the FIN flag to a TCP packet (as returned by make_tcp_packet)."""
    header = p[0]
    flags = struct.unpack('>B', header[13])[0]
    flags |= 0x01
    flags_byte = struct.pack('>B', flags)
    new_header = header[:13] + flags_byte + header[14:]
    return (new_header, p[1])

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
        assert self.__cmp__(s2) <= 0 , "segement 2 must not start earlier"

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
    """Manages the state of one half of a TCP connection."""
    def __init__(self, syn_seq, my_ip, my_port, other_ip, other_port,
                 connection_over_callback, has_data_to_send_callback,
                 assumed_rtt=0.5, mtu=1500, max_data=2048, max_wait_time_sec=5):
        # socket pair
        self.my_ip = my_ip
        self.my_port = my_port
        self.other_ip = other_ip
        self.other_port = other_port

        # TCP configuration
        self.rtt = assumed_rtt
        self.mtu = mtu
        self.max_data = max_data
        self.max_wait_time_sec = max_wait_time_sec
        self.last_activity = time.time()
        reactor.callLater(self.max_wait_time_sec, self.__check_wait_time)

        # callbacks
        self.connection_over_callback = lambda : connection_over_callback(self)
        self.has_data_to_send_callback = lambda : has_data_to_send_callback(self)

        # info about this side of the TCP connection
        self.segments = []
        self.next_seq_needed = syn_seq + 1
        self.need_to_send_ack = False
        self.need_to_send_data = True # need to send a SYN
        self.received_fin = False
        self.closed = False
        self.dead = False

        # information about outgoing data and relevant ACKs
        self.window = 0
        self.data_to_send = ''
        self.num_data_bytes_acked = 0
        self.first_unacked_seq = random.randint(0, 0x8FFFFFFF)
        self.last_seq_sent = self.first_unacked_seq
        self.my_syn_acked = False
        self.all_data_sent = True
        self.my_fin_sent = False
        self.my_fin_acked = False
        self.next_resend = 0
        self.reset_resend_timer()

    def add_segment(self, segment):
        """Merges segment into the bytes already received.  Raises socket.error
        if this segment indicates that the data block will exceed the maximum
        allowed."""
        if len(self.segments) > 0 and segment.next-self.segments[0].seq>self.max_data:
            raise socket.error('maximum data limit exceeded')

        self.__add_segment(segment)
        if len(self.segments) > 0 and self.segments[0].next > self.next_seq_needed:
            self.__note_activity()
            self.next_seq_needed = self.segments[0].next
            self.__need_to_send_now() # ACK the new data

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

    def add_data_to_send(self, data):
        """Adds data to be sent to the other side of the connection.  Raises
        socket.error if the socket is closed."""
        if not self.closed:
            logging.debug('Adding %dB to send (%dB already waiting)' % (len(data), len(self.data_to_send)))
            self.data_to_send += data
            self.all_data_sent = False
            self.__need_to_send_now(True) # send the data
        else:
            raise socket.error('cannot send data on a closed socket')

    def __check_wait_time(self):
        """Checks to see if this connection has been idle for longer than
        allowed.  If so, it is marked as dead and the connection_over_callback
        is called."""
        if time.time() - self.last_activity > self.max_wait_time_sec:
            self.connection_over_callback()
            self.dead = True
        else:
            reactor.callLater(self.max_wait_time_sec, self.__check_wait_time)

    def close(self):
        """Closes this end of the connection.  Will cause a FIN to be sent if
        the connection was not already closed.  The connection will be call
        its connection over callback TCPConnection.WAIT_TIME_SEC later."""
        if not self.closed:
            self.closed = True
            self.__need_to_send_now() # send the FIN

    def fin_received(self, seq):
        """Indicates that a FIN has been received from the other side."""
        self.received_fin = True
        self.next_seq_needed = seq + 1
        self.__need_to_send_now() # ACK the FIN

    def __get_ack_num(self):
        """Returns the sequence number we should use for the ACK field on
        outgoing packets."""
        return self.next_seq_needed

    def get_data(self):
        """Returns the data received so far (up to the first gap, if any)."""
        if self.segments:
            return self.segments[0].data
        else:
            return ''

    def get_socket_pair(self):
        """Returns the socket pair describing this connection (other then self)."""
        return ((self.other_ip, self.other_port), (self.my_ip, self.my_port))

    def has_data_to_send(self):
        """Returns True if there is an unACK'ed data waiting to be sent."""
        return self.num_unacked_data_bytes() > 0

    def has_ready_data(self):
        """Returns True if data has been received and there are no gaps in it."""
        logging.debug('# segments = %d' % len(self.segments))
        return len(self.segments) == 1

    def __need_to_send_now(self, data_not_ack=False):
        """The next call to get_packets_to_send will ensure an ACK is sent as
        well as any unacknowledged data."""
        if data_not_ack:
            self.need_to_send_data = True
        else:
            self.need_to_send_ack = True
        if self.has_data_to_send_callback:
            self.has_data_to_send_callback()

    def __note_activity(self):
        """Marks the current time as the last active time."""
        self.last_activity = time.time()

    def num_unacked_data_bytes(self):
        """Returns the number of outgoing data bytes which have not been ACK'ed."""
        return len(self.data_to_send) - self.num_data_bytes_acked

    def reset_resend_timer(self):
        """Resets the retransmission timer."""
        self.next_resend = time.time() + 2*self.rtt
        reactor.callLater(2*self.rtt, self.has_data_to_send_callback)

    def set_ack(self, ack):
        """Handles receipt of an ACK."""
        if ack-1 > self.last_seq_sent:
            logging.warn("truncating an ACK for bytes we haven't sent: ack=%d last_seq_sent=%d" % (ack, self.last_seq_sent))
            ack = self.last_seq_sent + 1 # assume they meant to ack all bytes we have sent

        diff = ack - self.first_unacked_seq
        if diff > 0:
            self.__note_activity()
            self.reset_resend_timer()
            if not self.my_syn_acked:
                diff = diff - 1
                self.my_syn_acked = True

            if diff > self.num_unacked_data_bytes():
                self.my_fin_acked = True
                diff = self.num_unacked_data_bytes()

            self.num_data_bytes_acked += diff

            #logging.debug('received ack %d (last unacked was %d) => %dB less to send (%dB left)' % \
            #              (ack, self.first_unacked_seq, diff, self.num_unacked_data_bytes()))
            self.first_unacked_seq = ack

            # if data has been ACK'ed, then send more if we have any
            if diff > 0 and not self.all_data_sent and self.has_data_to_send():
                self.__need_to_send_now(True)

    def get_packets_to_send(self):
        """Returns a list of packets which should be sent now."""
        ret = []
        if self.dead:
            return ret

        # is it time to send data?
        retransmit = False
        now = time.time()
        if now < self.next_resend:
            if not self.need_to_send_ack and not self.need_to_send_data:
                logging.debug('not time to send any packets yet (now=%d next=%d)' % (now, self.next_resend))
                return ret
        else:
            logging.debug('retransmit timer has expired: will retransmit %dB outstanding bytes', self.last_seq_sent-self.first_unacked_seq+1)
            retransmit = True

        # do we have something to send?
        if not self.my_syn_acked:
            logging.debug('Adding my SYN packet to the outgoing queue')
            ret.append(make_tcp_packet(self.my_port, self.other_port,
                                       seq=self.first_unacked_seq,
                                       ack=self.__get_ack_num(),
                                       data='',
                                       is_syn=True))

        sz = self.num_unacked_data_bytes()
        base_offset = self.first_unacked_seq + (0 if self.my_syn_acked else 1)
        if sz > 0:
            # figure out how many chunks we can send now
            data_chunk_size = self.mtu - 40  # 20B IP and 20B TCP header: rest for data
            num_chunks_left = sz / data_chunk_size
            outstanding_bytes = self.last_seq_sent - self.first_unacked_seq + 1
            max_outstanding_chunks = self.window / data_chunk_size
            num_chunks_to_send_now = min(num_chunks_left, max_outstanding_chunks)
            logging.debug('Will make sure %d chunks are out now (%d chunks total remain): chunk size=%dB, window=%dB=>%d chunks may be out, outstanding=%dB' % \
                          (num_chunks_to_send_now, num_chunks_left, data_chunk_size, self.window, max_outstanding_chunks, outstanding_bytes))
            # create the individual TCP packets to send
            for i in range(1+num_chunks_to_send_now):
                # determine what bytes and sequence numbers this chunk includes
                start_index = i * data_chunk_size
                end_index_plus1 = min(sz, start_index + data_chunk_size) # exclusive
                if end_index_plus1 == sz:
                    self.all_data_sent = True
                start_seq = base_offset + start_index
                end_seq = start_seq + end_index_plus1 - start_index - 1 # inclusive

                # manage retransmissions ...
                if not retransmit:
                    if end_seq <= self.last_seq_sent:
                        continue # we've sent this segment before; don't retransmit it yet
                    diff = self.last_seq_sent - start_seq + 1
                    if diff > 0:
                        # we've sent part of this segment before: only send the new stuff
                        start_seq += diff
                        start_index += 1

                # indices are relative to the first unsent byte: transform these
                # to the actual queue (i.e., skip the ACK'ed bytes)
                start_index += self.num_data_bytes_acked
                end_index_plus1 += self.num_data_bytes_acked

                # track the latest byte we've sent and formulate this chunk into a packet
                self.last_seq_sent = max(self.last_seq_sent, end_seq)
                logging.debug('Adding data bytes from %d to %d (inclusive) to the outgoing queue' % (start_seq, end_seq))
                ret.append(make_tcp_packet(self.my_port, self.other_port,
                                           seq=start_seq,
                                           ack=self.__get_ack_num(),
                                           data=self.data_to_send[start_index:end_index_plus1]))

        # send a FIN if we're closed, our FIN hasn't been ACKed, and we've sent
        # all the data we were asked to already (or there isn't any)
        if self.closed and not self.my_fin_acked and (self.all_data_sent or sz<=0):
            if not self.my_fin_sent or retransmit:
                if ret:
                    logging.debug('Making the last packet a FIN packet')
                    ret[-1] = add_fin_to_tcp_packet(ret[-1])
                else:
                    logging.debug('Adding my FIN packet to the outgoing queue')
                    ret.append(make_tcp_packet(self.my_port, self.other_port,
                                               seq=base_offset + sz,
                                               ack=self.__get_ack_num(),
                                               data='',
                                               is_fin=True))
            if not self.my_fin_sent:
                self.my_fin_sent = True
                self.last_seq_sent += 1

        if not ret and self.need_to_send_ack:
            logging.debug('Adding a pure ACK to the outgoing queue (nothing to piggyback on)')
            ret.append(make_tcp_packet(self.my_port, self.other_port,
                                       seq=self.first_unacked_seq,
                                       ack=self.__get_ack_num(),
                                       data=''))

        if ret:
            self.reset_resend_timer()
            self.need_to_send_ack = False
        return ret

class TCPServer():
    """Implements a basic TCP Server which handles raw TCP packets passed to it."""
    # Pass this value to the constructor and the TCPServer will accept connections on any port.
    ANY_PORT = 0

    def __init__(self, port, max_active_conns=25):
        """port is the port the TCPServer should listen for SYN packets on."""
        assert port>=0 and port<65536, "Port must be between 0 and 65536 (exclusive) or TCPServer.ANY_PORT"
        self.connections = {}
        self.listening_port_nbo = struct.pack('>H', port)
        self.max_active_conns = max_active_conns

    def __connection_over(self, conn):
        """Called when it is ready to be removed.  Removes the connection."""
        socket_pair = conn.get_socket_pair()
        logging.debug('connection over callback from: %s' % str(socket_pair))
        try:
            del self.connections[socket_pair]
        except KeyError:
            logging.warn('Tried to remove connection which is not in our dictionary: %s' % str(socket_pair))

    def __connection_has_data_to_send(self, conn):
        """Called when a connection has data to send."""
        pass

    def get_port_nbo(self):
        """Returns the 2-byte NBO representation of the port being listened on."""
        return self.listening_port_nbo

    def handle_tcp(self, pkt):
        """Processes pkt as if it was just received.  pkt should be a valid TCP
        packet.  Returns the TCPConnection pkt is associated with, if any."""
        assert pkt.is_tcp() and pkt.is_valid_tcp(), "TCPServer.handle_tcp expects a valid TCP packet as input"

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
                if len(self.connections) >= self.max_active_conns:
                    logging.info('Ignoring new connection request: already have %d active connections (the max)' % self.max_active_conns)
                    return None

                conn = TCPConnection(seq, pkt.ip_dst, pkt.tcp_dst_port, pkt.ip_src, pkt.tcp_src_port, self.__connection_over, self.__connection_has_data_to_send)
                self.connections[socket_pair] = conn
                logging.debug('received TCP SYN packet -- new connection created: %s' % conn)
            else:
                logging.debug('ignoring TCP packet without SYN for socket pair with no existing connection')
                return None # this tcp fragment is not part of an active session: ignore it

        # pull out the data
        if len(pkt.tcp_data):
            logging.debug('Adding segment for %d bytes received' % len(pkt.tcp_data))
            try:
                conn.add_segment(TCPSegment(seq, pkt.tcp_data))
            except socket.error:
                logging.debug('Maximum data allowed for a connection exceeded: closing it')
                conn.close()
                return None

        if pkt.is_tcp_fin():
            conn.fin_received(seq)

        # remember window and latest ACK
        conn.window = max(1460, window)  # ignore requests to shrink the window below an MTU
        if pkt.is_tcp_ack():
            conn.set_ack(ack)
        return conn
