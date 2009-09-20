"""Provides basic packet decoding and manipulation facilities."""

import struct

HTTP_PORT = struct.pack('> H', 80) # normally 80

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
    combined = pseudo_hdr + tcp_hdr_with_zero_csum + tcp_data

    if len(combined) & 1:
        combined = combined + '\x00'

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
            self.ip_proto = ip[9]
            self.ip_src = ip[12:16]
            self.ip_dst = ip[16:20]
            payload = ip[ip_hlen:]
            if self.is_tcp() and len(payload)>=20:
                self.__decode_tcp(payload)
            else:
                self.ip_payload = payload

    def __decode_tcp(self, tcp):
        tcp_hlen = 4 * ((struct.unpack('> B', tcp[12])[0] & 0xF0) >> 4)
        if tcp_hlen >= 20:
            self.tcp = tcp[:tcp_hlen]
            self.tcp_src_port = tcp[0:2]
            self.tcp_dst_port = tcp[2:4]
            self.tcp_control_bits = struct.unpack('>B', tcp[13])[0] & 0x3F
            self.tcp_data = tcp[tcp_hlen:]

    def get_reversed_eth(self):
        """Returns the Ethernet header with its source and destination fields reversed."""
        return self.mac_src + self.mac_dst + self.ether_type

    def get_reversed_ip(self, new_ttl=None):
        """Returns the IP header with its source and destination fields reversed
        as well as the TTL field set and the checksum updated appropriately."""
        if new_ttl is None:
            str_ttl = self.ip[8]
        else:
            str_ttl = struct.pack('>B', new_ttl)
        hdr = self.ip[0:8] + str_ttl + self.ip[9:12] + self.ip_dst + self.ip_src
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

    @staticmethod
    def cksum_ip_hdr(ip_hdr):
        """Returns the provided IP header with the checksum set."""
        hdr_with_zero_csum = ip_hdr[0:10] + '\x00\x00' + ip_hdr[12:]
        csum = checksum(hdr_with_zero_csum)
        return ip_hdr[0:10] + struct.pack('> H', csum) + ip_hdr[12:]

    @staticmethod
    def cksum_tcp_hdr(ip_hdr, tcp_hdr, tcp_data):
        """Returns the provided TCP header with the checksum set."""
        csum = tcp_checksum(ip_hdr, tcp_hdr, tcp_data)
        return tcp_hdr[0:16] + struct.pack('> H', csum) + tcp_hdr[18:]

    def modify_tcp_packet(self, new_dst_ip, new_dst_port, new_src_port,
                          reverse_eth=True):
        """Returns this Ethernet frame (which must contain a TCP header) altered
        so that it is now addressed to the specified IP address and port (IP and
        TCP checksums are updated appropriately); the Ethernet src/dst MACs are
        also swapped if reverse_eth is True."""
        new_eth_hdr = self.get_reversed_eth() if reverse_eth else self.eth
        new_ip_hdr = Packet.cksum_ip_hdr(self.ip[0:16] + new_dst_ip + self.ip[20:])

        new_tcp_hdr_wo_csum = new_src_port + new_dst_port + self.tcp[4:]
        new_tcp_hdr = Packet.cksum_tcp_hdr(new_ip_hdr,
                                           new_tcp_hdr_wo_csum,
                                           self.tcp_data)

        return new_eth_hdr + new_ip_hdr + new_tcp_hdr + self.tcp_data
