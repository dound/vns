"""Provides basic packet decoding and manipulation facilities."""

import struct

HTTP_PORT = struct.pack('> H', 80) # normally 80
HTTP_ALT_PORT = struct.pack('> H', 8080) # normally 8080

def is_http_port(port):
    return port==HTTP_PORT or port==HTTP_ALT_PORT

def checksum(buf):
    """One's complement 16-bit checksum."""
    # ensure multiple of two length
    if len(buf) & 1:
        buf = buf + '\0'
    sz = len(buf)

    # add all 16 bit pairs into the total
    num_shorts = sz / 2
    tot = sum(struct.unpack('> %uH' % num_shorts, buf))

    # fold any carries back into the lower 16 bits
    tot = (tot >> 16) + (tot & 0xFFFF) # add hi 16 to low 16
    tot += (tot >> 16)                 # add carry
    return (~tot) & 0xFFFF             # truncate to 16 bits

def tcp_checksum(ip_hdr, tcp_hdr, tcp_data):
    """Computes the TCP checksum for the given TCP/IP data."""
    total_len = struct.pack('> H', len(tcp_hdr) + len(tcp_data))
    pseudo_hdr = ip_hdr[12:20] + '\x00' + ip_hdr[9] + total_len
    tcp_hdr_with_zero_csum = tcp_hdr[0:16] + '\x00\x00' + tcp_hdr[18:]
    pad = '\x00' if len(tcp_data) & 1 else ''
    combined = tcp_hdr_with_zero_csum + tcp_data + pad + pseudo_hdr
    return checksum(combined)

class Packet:
    """Provides trivial decoding of Ethernet, IP, and TCP protocols."""
    def __init__(self, eth):
        """Decodes the specified Ethernet frame into its constituent headers."""
        eth_hlen = 14
        self.eth = eth[:eth_hlen]
        self.mac_dst = eth[0:6]
        self.mac_src = eth[6:12]
        self.ether_type   = eth[12:14]
        payload = eth[eth_hlen:]

        self.arp = self.ip = self.tcp = None
        if self.is_ip() and len(payload)>=20:
            self.__decode_ip(payload)
        elif self.is_arp() and len(payload)>=28:
            self.__decode_arp(payload)

    def __decode_arp(self, arp):
        if arp[0:2]   != '\x00\x01': # must be Ethernet HW type
            return
        elif arp[2:4] != '\x08\x00': # must be IP protocol type
            return
        elif arp[4]   != '\x06':     # must be 6B Ethernet address
            return
        elif arp[5]   != '\x04':     # must be 4B IP address
            return

        self.arp = arp
        self.arp_type = arp[6:8]
        self.sha = arp[8:14]
        self.spa = arp[14:18]
        self.dha = arp[18:24]
        self.dpa = arp[24:28]

    def __decode_ip(self, ip):
        ver_and_hlen = struct.unpack('> B', ip[0])[0]
        ver = (ver_and_hlen & 0xF0) >> 4
        ip_hlen = 4 * (ver_and_hlen & 0x0F)

        if ver==4 and ip_hlen>=20:
            self.ip = ip[:ip_hlen]
            self.ip_hlen = ip_hlen
            self.ip_tlen = struct.unpack('>H', ip[2:4])[0]
            self.ip_proto = ip[9]
            self.ip_src = ip[12:16]
            self.ip_dst = ip[16:20]
            payload = ip[ip_hlen:]
            if self.is_tcp() and len(payload)>=20:
                self.__decode_tcp(payload)
            self.ip_payload = payload

    def __decode_tcp(self, tcp):
        tcp_hlen = 4 * ((struct.unpack('> B', tcp[12])[0] & 0xF0) >> 4)
        if tcp_hlen >= 20:
            self.tcp = tcp[:tcp_hlen]
            self.tcp_src_port = tcp[0:2]
            self.tcp_dst_port = tcp[2:4]
            self.tcp_hlen = tcp_hlen
            self.tcp_control_bits = struct.unpack('>B', tcp[13])[0] & 0x3F
            tcp_data_len = self.ip_tlen - tcp_hlen - self.ip_hlen
            self.tcp_data = tcp[tcp_hlen:tcp_hlen+tcp_data_len]

    def get_reversed_eth(self, new_mac_dst=None):
        """Returns the Ethernet header with its source and destination fields reversed."""
        if not new_mac_dst:
            new_mac_dst = self.mac_dst
        return self.mac_src + new_mac_dst + self.ether_type

    def get_reversed_ip(self, new_ttl=None, new_proto=None, new_tlen=None):
        """Returns the IP header with its source and destination fields reversed
        as well as the TTL field set and the checksum updated appropriately.  If
        new_ttl and/or new_proto are specified, they will replace the original
        TTL/protocol fields.  They should be specified as plain integer values."""
        if new_ttl is None:
            str_ttl = self.ip[8]
        else:
            str_ttl = struct.pack('>B', new_ttl)
        if new_proto is None:
            str_proto = self.ip_proto
        else:
            str_proto = struct.pack('>B', new_proto)
        if new_tlen is None:
            str_tlen = self.ip[2:4]
        else:
            str_tlen = struct.pack('>H', new_tlen)
        hdr = self.ip[0:2] + str_tlen + self.ip[4:8] + str_ttl + str_proto + self.ip[10:12] + self.ip_dst + self.ip_src
        return Packet.cksum_ip_hdr(hdr)

    def is_dst_mac_broadcast(self):
        """Returns True if the destination MAC address is 0xFFFFFFFFFFFF."""
        return self.mac_dst == '\xFF\xFF\xFF\xFF\xFF\xFF'

    def is_arp(self):
        """Returns True if ethertype is 0x0806 (ARP)."""
        return self.ether_type == '\x08\x06'

    def is_valid_arp(self):
        """Returns True if this packet has an ARP header."""
        return self.arp and len(self.arp) >= 28

    def is_arp_request(self):
        """Returns True if arp_type is 0x0001."""
        return self.is_valid_arp() and self.arp_type == '\x00\x01'

    def is_arp_reply(self):
        """Returns True if arp_type is 0x0002."""
        return self.is_valid_arp() and self.arp_type == '\x00\x02'

    def is_ip(self):
        """Returns True if ethertype is 0x0800 (IP)."""
        return self.ether_type == '\x08\x00'

    def is_valid_ipv4(self):
        """Returns True if this packet has an IPv4 header."""
        if self.ip and len(self.ip) >= 20:
            ver = (struct.unpack('>B',self.ip[0])[0] & 0xF0) >> 4
            return ver == 4
        else:
            return False

    def is_tcp(self):
        """Returns True if this packet is a valid IPv4 packet containing TCP."""
        return self.is_valid_ipv4() and self.ip[9] == '\x06'

    def is_valid_tcp(self):
        """Returns True if this packet has a TCP header."""
        return self.tcp and len(self.tcp) >= 20

    def is_tcp_fin(self):
        """Returns True if the FIN flag is set."""
        return (self.tcp_control_bits & 0x01) == 0x01

    def is_tcp_syn(self):
        """Returns True if the SYN flag is set."""
        return (self.tcp_control_bits & 0x02) == 0x02

    def is_tcp_rst(self):
        """Returns True if the RST flag is set."""
        return (self.tcp_control_bits & 0x04) == 0x04

    def is_tcp_ack(self):
        """Returns True if the ACK flag is set."""
        return (self.tcp_control_bits & 0x10) == 0x10

    @staticmethod
    def cksum_ip_hdr(ip_hdr):
        """Returns the provided IP header with the checksum set."""
        hdr_with_zero_csum = ip_hdr[0:10] + '\x00\x00' + ip_hdr[12:]
        csum = checksum(hdr_with_zero_csum)
        return ip_hdr[0:10] + struct.pack('> H', csum) + ip_hdr[12:]

    @staticmethod
    def cksum_icmp_pkt(icmp_pkt):
        """Returns the provided ICMP header with the checksum set."""
        icmp_with_zero_csum = icmp_pkt[0:2] + '\x00\x00' + icmp_pkt[4:]
        csum = checksum(icmp_with_zero_csum)
        return icmp_pkt[0:2] + struct.pack('> H', csum) + icmp_pkt[4:]

    @staticmethod
    def cksum_tcp_hdr(ip_hdr, tcp_hdr, tcp_data):
        """Returns the provided TCP header with the checksum set."""
        csum = tcp_checksum(ip_hdr, tcp_hdr, tcp_data)
        return tcp_hdr[0:16] + struct.pack('> H', csum) + tcp_hdr[18:]

    def generate_icmp_dst_unreach(self):
        """Generates an ICMP destination unreachable message for this IP packet.
        The ICMP portion of the message is returned."""
        icmp_hdr = '\x03\x03\x80\xec' # dest unreach: port unreach w/cksum
        # data is four "0" bytes followed by the IP header and 8B of its payload
        icmp_data = '\x00\x00\x00\x00' + self.ip + self.ip_payload[:8]
        return Packet.cksum_icmp_pkt(icmp_hdr + icmp_data)

    def generate_complete_icmp_dst_unreach(self):
        """Generates an ICMP destination unreachable message for this IP packet.
        The full Ethernet frame is constructed, assuming the packet will be sent
        back via the way it came."""
        new_eth = self.get_reversed_eth()
        new_icmp = self.generate_icmp_dst_unreach()
        tlen = len(self.ip) + len(new_icmp)
        new_ip = self.get_reversed_ip(new_ttl=64, new_proto=1, new_tlen=tlen)
        return new_eth + new_ip + new_icmp

    def modify_tcp_packet(self,
                          new_src_ip, new_src_port,
                          new_dst_ip, new_dst_port,
                          reverse_eth=True):
        """Returns this Ethernet frame (which must contain a TCP header) altered
        so that it is now addressed to the specified IP address and port (IP and
        TCP checksums are updated appropriately); the Ethernet src/dst MACs are
        also swapped if reverse_eth is True."""
        new_eth_hdr = self.get_reversed_eth() if reverse_eth else self.eth
        new_ip_hdr = Packet.cksum_ip_hdr(self.ip[0:12] + new_src_ip + new_dst_ip + self.ip[20:])

        new_tcp_hdr_wo_csum = new_src_port + new_dst_port + self.tcp[4:]
        new_tcp_hdr = Packet.cksum_tcp_hdr(new_ip_hdr,
                                           new_tcp_hdr_wo_csum,
                                           self.tcp_data)

        return new_eth_hdr + new_ip_hdr + new_tcp_hdr + self.tcp_data
