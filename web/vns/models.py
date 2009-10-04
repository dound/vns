import hashlib
from socket import inet_aton, inet_ntoa
import struct

from django.db.models import AutoField, BooleanField, CharField, DateField, \
                             DateTimeField, FloatField, ForeignKey, \
                             IntegerField, IPAddressField, ManyToManyField, Model
from django.contrib.auth.models import User

class Simulator(Model):
    """A VNS simulation server."""
    name = CharField(max_length=30, unique=True)
    ip = IPAddressField(unique=True,
                        help_text='IP address where the server is located.')
    gatewayIP = IPAddressField(help_text='First hop IP address outside of the simulator.')
    gatewayMAC = CharField(max_length=17, help_text='Ethernet address in the form AB:CD:EF:GH:IJ:KL')

    def __unicode__(self):
        return u'%s' % self.name

class Organization(Model):
    """An institution to which a group of users belong (or a sub-group)."""
    name = CharField(max_length=30, unique=True)
    parentOrg = ForeignKey('self', null=True, blank=True)
    boss = ForeignKey(User, related_name='org_boss_id',
                      help_text='User with complete control of this organization.')
    admins = ManyToManyField(User, null=True, blank=True)

    def __unicode__(self):
        return u'%s' % self.name

class UserProfile(Model):
    """Defines extra information to associate with a User."""
    POSITION_CHOICES = (
        (0, u'VNS Admin'),
        (1, u'Student'),
        (3, u'Instructor'),
        (4, u'TA'),
    )

    user = ForeignKey(User, unique=True)
    org  = ForeignKey(Organization)
    pos  = IntegerField(choices=POSITION_CHOICES)

    def __unicode__(self):
        return u'%s' % self.user.__unicode__()

class TopologyTemplate(Model):
    """A template network topology.  This includes the nodes, links, and subnet
    information."""
    VISIBILITY_CHOICES = (
        (0, u'Private - owner only'),
        (1, u'Protected - owner and organization only'),
        (2, u'Public - anyone'),
    )

    name = CharField(max_length=30, unique=True)
    date_updated = DateField(auto_now=True, auto_now_add=True)
    owner = ForeignKey(User,
                       help_text='The user who created the template.')
    org = ForeignKey(Organization,
                     help_text='The organization this template belongs to.')
    visibility = IntegerField(choices=VISIBILITY_CHOICES,
                              help_text='Who may see and use this template.')

    def __unicode__(self):
        return u'%s' % self.name

class Node(Model):
    """A node in a topology template."""
    VIRTUAL_NODE_ID = 0
    BLACK_HOLE_ID = 1
    HUB_ID = 2
    WEB_SERVER_ID = 3
    GATEWAY_ID = 4
    NODE_CHOICES = (
        (VIRTUAL_NODE_ID, u'Virtual Node'),
        (BLACK_HOLE_ID, u'Black Hole'),
        (HUB_ID, u'Hub'),
        (WEB_SERVER_ID, u'Web Server'),
        (GATEWAY_ID, u'Gateway Router'), # b/w simulator and the real world, OR
                                         # perhaps even between two simulators
    )

    template = ForeignKey(TopologyTemplate)
    name = CharField(max_length=30)
    type = IntegerField(choices=NODE_CHOICES)

    def __unicode__(self):
        return u'%s: %s' % (self.template.name, self.name)

class WebServerHostname(Model):
    """A web server hostname which can be proxied by a simulated web server."""
    hostname = CharField(max_length=256)

    def get_ascii_hostname(self):
        return self.hostname.encode('ascii')

    def __unicode__(self):
        return self.hostname

class WebServer(Node):
    """A web server node.  It specifies which web server it will proxy (i.e.,
    if you connect to it, what website will it appear to serve).  This is
    limited to choices in the WebServerHostname table to prevent users from
    using the system to retrieve content from questionable sources."""
    web_server_addr = ForeignKey(WebServerHostname)
    replace_hostname_in_http_replies = \
        BooleanField(default=True,
                     help_text='If true, then HTTP replies will have any ' + \
                               'occurrence of the hostname within the "href"' + \
                               'field of the "a" tag replaced with this ' + \
                               'node\'s IP address.')

    def __unicode__(self):
        return Node.__unicode__(self) + ' -> %s' % self.web_server_addr.__unicode__()

class Port(Model):
    """A port on a node in a topology template."""
    node = ForeignKey(Node)
    name = CharField(max_length=5)

    def __unicode__(self):
        return u'%s: %s: %s' % (self.node.template.name, self.node.name, self.name)

class Link(Model):
    """A link connecting two nodes in a topology template."""
    port1 = ForeignKey(Port, related_name='port1_id')
    port2 = ForeignKey(Port, related_name='port2_id')
    lossiness = FloatField(default=0.0,
                           help_text='% of packets lost by this link: [0.0, 1.0]')

    def __unicode__(self):
        return u'%s: %s:%s <--> %s:%s' % (self.port1.node.template.name,
                                          self.port1.node.name, self.port1.name,
                                          self.port2.node.name, self.port2.name)

class Topology(Model):
    """An instantiation of a topology template."""
    id = AutoField(primary_key=True,
                   help_text='Users will connect virtual nodes to this ' +
                             'topology by specifying this number.')
    owner = ForeignKey(User)
    template = ForeignKey(TopologyTemplate)
    enabled = BooleanField(help_text='Whether this topology is active.')
    public = BooleanField(help_text='Whether any user may connect to a node on this topology.')

    def __unicode__(self):
        str_enabled = '' if self.enabled else ' (disabled)'
        return u'Topology %d%s' % (self.id, str_enabled)

def base_subnet(subnet_str):
    """Converts a subnet string to just the (masked) prefix."""
    str_prefix, str_mask_bits = subnet_str.split('/')
    ip_int = struct.unpack('>I', inet_aton(str_prefix))[0]
    n = int(str_mask_bits)
    mask = int(n*'1' + (32-n)*'0', 2)
    return inet_ntoa(struct.pack('>I', ip_int & mask))

class TopologySourceIPFilter(Model):
    """Lists the IP addresses which may interact with a topology through the
    simulator.  If no IPs are listed, then there will be no restrictions.  This
    is most useful for enabling different topologies to share (reuse) simulator
    IPs."""
    topology = ForeignKey(Topology)
    ip = IPAddressField()
    mask = IntegerField(choices=tuple([(i, u'/%d'%i) for i in range(1,33)]),
                        help_text='Number of bits which are dedicated to a' +
                                  'common routing prefix.')

    def subnet_str(self):
        """Returns the string IP/mask."""
        # TODO: rather than processing with base_subnet now, we should validate
        #       db entries as they are created to be in this form
        raw_subnet_str = '%s/%d' % (self.ip, self.mask)
        return base_subnet(raw_subnet_str)

    def md5(self):
        """Returns the MD5 sum of the string IP/mask."""
        return hashlib.md5(self.subnet_str()).digest()

    def __unicode__(self):
        return u'%s may interact with %s' % (self.subnet_str(), self.topology.__unicode__())

class TopologyUserFilter(Model):
    """Lists the users which may interact with a topology by connecting to a
    virtual client in the topology.  A topology's owner always has this privilege."""
    topology = ForeignKey(Topology)
    user = ForeignKey(User)

    def __unicode__(self):
        return u'%s may interact with %s' % (self.user(), self.topology.__unicode__())

class IPAssignment(Model):
    """Maps an IP address to a port on a particular node in a particular
    topology.  IPs may be assigned to more than one node based on constraints
    enforced at a higher level."""
    topology = ForeignKey(Topology)
    port = ForeignKey(Port)
    ip = IPAddressField()
    mask = IntegerField(choices=tuple([(i, u'/%d'%i) for i in range(1,33)]),
                        help_text='Number of bits which are dedicated to a' +
                                  'common routing prefix.')

    def get_ip(self):
        """Returns the 4-byte integer representation of the IP."""
        return inet_aton(self.ip)

    def get_mask(self):
        """Returns the 4-byte integer representation of the subnet mask."""
        return struct.pack('>I', 0xffffffff ^ (1 << 32 - self.mask) - 1)

    def get_mac(self, salt=''):
        """Maps the string representation of the IP address (as well as any
        salt, if given) into a 6B MAC address whose first byte is 0."""
        return '\x00' + hashlib.md5(self.ip.encode('ascii') + salt).digest()[0:5]

    def __unicode__(self):
        return u'%s: %s <== %s/%d' % (self.topology.__unicode__(),
                                      self.port.__unicode__(), self.ip, self.mask)

class MACAssignment(Model):
    """Maps a MAC address to a port on a particular node in a particular topology."""
    topology = ForeignKey(Topology)
    port = ForeignKey(Port)
    mac = CharField(max_length=17, help_text='Ethernet address in the form AB:CD:EF:GH:IJ:KL')

    def get_mac(self):
        """Returns the 6B byte-string form of the MAC address."""
        octets = self.mac.split(':')
        assert(len(octets) == 6)
        return struct.pack('> 6B', [int(h, 16) for h in octets])

class IPBlock(Model):
    """A block of IP addresses which can be allocated to topologies in a
    particular simulator."""
    simulator = ForeignKey(Simulator,
                           help_text='The simulator which owns this block.')
    parentIPBlock = ForeignKey('self', null=True, blank=True,
                               help_text='The larger block to which this belongs.')
    org = ForeignKey(Organization)
    subnet = IPAddressField()
    mask = IntegerField('Subnet Mask (# of significant bits in the subnet)')

    def __unicode__(self):
        return u'%s/%d' % (self.subnet, self.mask)

class StatsTopology(Model):
    """Statistics about Topology during a single session."""
    template = ForeignKey(TopologyTemplate)
    client_ip = IPAddressField(help_text='IP address of the first client to connect to the topology')
    username = CharField(max_length=100)
    time_connected = DateTimeField(auto_now_add=True)
    total_time_connected_sec = IntegerField(default=0)
    num_pkts_to_topo = IntegerField(default=0, help_text='Counts packets arriving from the real world or through the topology interaction protocol.')
    num_pkts_from_topo = IntegerField(default=0, help_text='Counts packets sent from the topology out to the real world.')
    num_pkts_to_client = IntegerField(default=0, help_text='Counts packets sent to any client node in the topology.')
    num_pkts_from_client = IntegerField(default=0, help_text='Counts packets sent from any client node in the topology.')
    active = BooleanField(default=True, help_text='True as long as this topology is still running on the simulator.')

    def init(self, template, client_ip, username):
        self.template = template
        self.client_ip = client_ip
        self.username = username
        self.changed = False

    def note_pkt_to_topo(self):
        self.num_pkts_to_topo += 1
        self.changed = True

    def note_pkt_from_topo(self):
        self.num_pkts_from_topo += 1
        self.changed = True

    def note_pkt_to_client(self):
        self.num_pkts_to_client += 1
        self.changed = True

    def note_pkt_from_client(self):
        self.num_pkts_from_client += 1
        self.changed = True

    def save_if_changed(self):
        if self.changed:
            self.changed = False
            self.save()

    def total_num_packets(self):
        return self.num_pkts_from_client + self.num_pkts_from_topo + self.num_pkts_to_client + self.num_pkts_to_topo

    def __unicode__(self):
        return (u'Template %s stats: ' % self.template.name) + \
               (u'Started by client %s at %s; ' % (self.username, self.client_ip)) + \
               (u'Active for %dsec; ' % self.total_time_connected_sec) + \
               (u'# Packets [Topo to=%d from=%d] ' % (self.num_pkts_to_topo, self.num_pkts_from_topo)) + \
               (u'[User to=%d from=%d]' % (self.num_pkts_to_client, self.num_pkts_from_client))
