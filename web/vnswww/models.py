import datetime
import hashlib
import math
import random
import re
from socket import inet_aton, inet_ntoa
import string
import struct

from django.db.models import AutoField, BooleanField, CharField, DateField, \
                             DateTimeField, FloatField, ForeignKey, Q, TextField, \
                             IntegerField, IPAddressField, ManyToManyField, Model
from django.contrib.auth.models import User

def get_delta_time_sec(t1, t2):
    """Returns the number of seconds between two times."""
    deltaT = t2 - t1
    return deltaT.seconds + 60*60*24*deltaT.days

def make_mask_field():
    return IntegerField(choices=tuple([(i, u'/%d'%i) for i in range(1,33)]),
                        help_text='Number of bits which are dedicated to a' +
                                  'common routing prefix.')

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

    SIM_KEY_SZ = 64 # size in bytes

    user = ForeignKey(User, unique=True)
    org  = ForeignKey(Organization)
    pos  = IntegerField(choices=POSITION_CHOICES)
    sim_key = CharField(max_length=SIM_KEY_SZ,
                        help_text="The ASCII string (system-generated) "+
                                  "which the user uses to authenticate with the simulator.")

    def get_sim_auth_key_bytes(self):
        """Returns a byte-string representation of the simulator auth key."""
        return ''.join(struct.pack('>B', ord(c)) for c in self.sim_key)

    def get_sim_auth_key(self):
        return self.sim_key

    def set_sim_auth_key(self, str):
        """Sets the simulator auth key to the specified hexidecimal string."""
        assert len(str)==UserProfile.SIM_KEY_SZ
        self.sim_key = str

    def generate_and_set_new_sim_auth_key(self):
        chars = string.ascii_letters + string.digits + string.punctuation
        self.set_sim_auth_key(''.join(random.choice(chars) for _ in range(UserProfile.SIM_KEY_SZ)))

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
    readme = TextField(help_text='Template of the readme which will explain ' + \
                       'the topology to the user.  Template tags start with $ ' + \
                       'and include the following: $topo.id, $sim.gatewayip, ' + \
                       "and $node.port.ip where node is a node's name and " + \
                       "port is a port's name (e.g., $Server1.eth0.ip).")

    def get_root_port(self):
        """Returns the "root" port of the topology.  This is the port connected
        to the gateway (if one exists).  Otherwise, it is the port whose name
        comes first on the node whose name comes first (lexicographic order).
        None is only returned if the template has no ports."""
        try:
            gw = Node.objects.get(template=self, type=Node.GATEWAY_ID)
            gw_port = Port.objects.get(node=gw)
            gw_link = Link.objects.get(Link.Q_either_port(gw_port))
            return gw_link.get_other(gw_port)
        except (Node.DoesNotExist, Port.DoesNotExist, Link.DoesNotExist):
            # no gateway, gateway port, or gateway link: just choose an
            # arbitrary port (first node and first port on that node [abc order])
            try:
                return Port.objects.filter(node__template=self).order_by('node__name', 'name')[0]
            except IndexError:
                return None # no ports in this topology

    README_REGEXP = re.compile(r'[$]\S+')
    def render_readme(self, sim, topo):
        # build the dictionary of all valid substitutions
        values = {}
        values['$topo.gatewayip'] = sim.gatewayIP
        values['$topo.id'] = topo.id
        for ipa in IPAssignment.objects.filter(port__node__template=self):
            values['$%s.%s.ip' % (ipa.port.name, ipa.port.node.name)] = ipa.ip

        # define a function for substituting the appropriate value for an exp
        def repl(m):
            try:
                return values[m.groups(0)]
            except KeyError:
                return m.groups(0) # no change

        # render the readme with all substitutions
        TopologyTemplate.README_REGEXP.sub(repl, self.readme)

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

class PortTreeNode():
    """A node in a tree of ports."""
    def __init__(self, port, subtree=[]):
        self.port = port
        self.subtree = subtree
        self.sz = None
        self.unmask_sz = None

    def assign_addr(self, start_addr, parent_node=None, parent_mask=None):
        """Assigns addresses to the tree of nodes rooted at this node.
        start_addr must be an aligned subnet containing 2**self.unmask_sz
        addresses (i.e., if unmask_sz is 3, then start_addr must have the lowest
        3 bits zeroed).  A list of 3-tuples is returned which contains the
        (port,address,mask) triples."""
        assert ((start_addr >> self.unmask_sz) << self.unmask_sz)==start_addr, 'start_addr=%d is not aligned to /%d' % (start_addr, 32-self.unmask_sz)

        # Choose the subnet mask of this assignment.  If DFS reached this port
        # through a port on the same node, then use the subnet mask associated
        # with the next layer (e.g., this PortTreeNode's own subnet size).
        # Otherwise, just go with the parent's subnet size.
        if self.port.node==parent_node or parent_mask is None:
            mask = 32 - self.unmask_sz
        else:
            mask = parent_mask

        # give myself the lowest address in this subnet
        ret = [(self.port, start_addr, mask)]
        start_addr += 1

        # give my subtrees addresses from the end of my block (go from large to small)
        num_addrs = 1 << self.unmask_sz # 2 ** unmask_sz
        for st in sorted(self.subtree):
            st_start = start_addr + num_addrs - st.sz - 1
            ret += st.assign_addr(st_start, self.port.node, mask)
            num_addrs -= st.sz
        return ret

    def compute_subnet_size(self, must_be_power_of_2=True):
        """Computes the number of ports in this subnet and all sub-subnets.  If
        must_be_power_of_2 is True, then each subnet will be rounded up to the
        nearest power of 2."""
        self.sz = 1 # count self.port
        for ptn in self.subtree:
            self.sz += ptn.compute_subnet_size(must_be_power_of_2)

        self.unmask_sz = int(math.ceil(math.log(self.sz, 2)))
        if must_be_power_of_2:
            self.sz = 1 << self.unmask_sz

        return self.sz

    def __cmp__(self, other):
        """Larger subtrees come before smaller subtrees (high to low).  Break
        ties by comparing interface name (reverse lexicographic order)."""
        if self.sz == other.sz:
            return cmp(other.port.name, self.port.name)
        else:
            return cmp(other.sz, self.sz)

    def __str__(self):
        str_self = '%s:%s' % (self.port.node.name, self.port.name)
        if self.subtree:
            str_st = ', '.join(ptn.__str__() for ptn in self.subtree)
            return '(%s --> [%s])' % (str_self, str_st)
        else:
            return str_self

class Port(Model):
    """A port on a node in a topology template."""
    node = ForeignKey(Node)
    name = CharField(max_length=5)
    ip_offset = IntegerField(default=-2,
                             help_text="Guides automatic IP assignment.  This "  + \
                             "value will be added to the root subnet IP to get " + \
                             "this port's IP.  If -1, then this port will not "  + \
                             "be assigned any IP.")

    def get_tree(self):
        """Returns the topology tree (from a depth-first search) rooted at this
        port excluding any ports attached to nodes in the completed_nodes
        dictionary.  In particular, the root node is returned.  Each node is a
        PortTreeNode consisting of the Port the node represents and a list of
        nodes (its subtrees)."""
        return self.__get_tree({})

    def __get_tree(self, completed_nodes):
        # the node this port is attached to is now on the completed list
        assert not completed_nodes.has_key(self.node), 'loop due to node re-exploration'
        completed_nodes[self.node] = True

        # get other ports on this node which haven't been touched yet
        other_ports = Port.objects.filter(node=self.node).exclude(name=self.name)
        if not other_ports:
            return PortTreeNode(self) # leaf!

        # non-leaf: connected to other ports
        subtree = []
        for port in other_ports:
            try:
                link = Link.objects.get(Link.Q_either_port(port))
                conn_port = link.get_other(port)
                if completed_nodes.has_key(conn_port.node):
                    # already explored the link from this port, so it has no new subtree to add
                    subtree.append(PortTreeNode(port))
                else:
                    subtree.append(PortTreeNode(port, [conn_port.__get_tree(completed_nodes)]))
            except Link.DoesNotExist:
                # no link from the other port, so it has no subtree
                subtree.append(PortTreeNode(port))

        return PortTreeNode(self, subtree)

    def __unicode__(self):
        return u'%s: %s: %s' % (self.node.template.name, self.node.name, self.name)

class Link(Model):
    """A link connecting two nodes in a topology template."""
    port1 = ForeignKey(Port, related_name='port1_id')
    port2 = ForeignKey(Port, related_name='port2_id')
    lossiness = FloatField(default=0.0,
                           help_text='% of packets lost by this link: [0.0, 1.0]')

    @staticmethod
    def Q_either_port(port):
        return Q(port1=port) | Q(port2=port)

    def get_other(self, port):
        if self.port1 == port:
            return self.port2
        else:
            return self.port1

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
    temporary = BooleanField(help_text='Whether this topology was only allocated temporarily.')

    def get_readme(self):
        """Returns the readme for this topology.  An error string will be returned
        if this topology is not assigned any IPs."""
        try:
            sim = IPBlockAllocation.objects.get(topology=self).block_from.simulator
            return self.template.render_readme(sim, self)
        except IPBlockAllocation.DoesNotExist:
            return 'The readme cannot be generated unless the topology is assigned IPs.'

    def get_where_ips_allocated(self):
        """Returns the block from which the IPs for this topology were allocated."""
        try:
            return IPBlockAllocation.objects.get(topology=self)
        except IPBlockAllocation.DoesNotExist:
            return 0

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
    mask = make_mask_field()

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
    mask = make_mask_field()

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
    usable_by_child_orgs = BooleanField(default=True, help_text='Whether ' + \
        'any organization whose parent is the organization who owns this ' + \
        'IP block may allocate IPs from this IP block.')

    def __unicode__(self):
        return u'%s/%d' % (self.subnet, self.mask)

class IPBlockAllocation(Model):
    """Marks a block of IP addresses as allocated to a particular topology."""
    block_from = ForeignKey(IPBlock)
    topology = ForeignKey(Topology, null=True, blank=True,
                          help_text='')
    start_addr = IPAddressField()
    mask = make_mask_field()

    def size(self):
        return 2 ** (32 - self.mask)

    def __unicode__(self):
        suffix = '%s/%d (from %s)' % (self.start_addr, self.mask, self.block_from)
        if self.topology:
            return u'%s <- %s' % (self.topology, suffix)
        else:
            return suffix

class RecentIPBlockAllocation(Model):
    """Tracks the IP allocation a user got for a particular template last time
    that user instantiated it."""
    user = ForeignKey(User)
    template = ForeignKey(TopologyTemplate)
    start_addr = IPAddressField()
    mask = make_mask_field()

    def __unicode__(self):
        return u'%s <- %s/%d (for %s)' % (self.template, self.start_addr, self.mask, self.user)

class StatsTopology(Model):
    """Statistics about Topology during a single session."""
    template = ForeignKey(TopologyTemplate)
    client_ip = IPAddressField(help_text='IP address of the first client to connect to the topology')
    username = CharField(max_length=100)
    time_connected = DateTimeField(auto_now_add=True)
    time_last_changed = DateTimeField(auto_now_add=True)
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
        self.time_last_changed = datetime.datetime.now()
        self.changed = False

    def finalize(self):
        self.active = False
        self.total_time_connected_sec = self.get_num_sec_connected()
        if not self.save_if_changed():
            self.save()

    def get_num_sec_connected(self):
        """Returns how long this topology has been connected."""
        if self.active:
            return get_delta_time_sec(self.time_connected, datetime.datetime.now())
        else:
            return self.total_time_connected_sec

    def get_idle_time_sec(self):
        """Returns the amount of time this topology has been idle in seconds."""
        if not self.active or (self.__dict__.has_key('changed') and self.changed):
            return 0
        else:
            return get_delta_time_sec(self.time_last_changed, datetime.datetime.now())

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
        """Saves these stats and returns True if they have changed."""
        if self.changed:
            self.changed = False
            self.time_last_changed = datetime.datetime.now()
            self.save()
            return True
        return False

    def total_num_packets(self):
        return self.num_pkts_from_client + self.num_pkts_from_topo + self.num_pkts_to_client + self.num_pkts_to_topo

    def __unicode__(self):
        return (u'Template %s stats: ' % self.template.name) + \
               (u'Started by client %s at %s; ' % (self.username, self.client_ip)) + \
               (u'Active for %dsec; ' % self.total_time_connected_sec) + \
               (u'# Packets [Topo to=%d from=%d] ' % (self.num_pkts_to_topo, self.num_pkts_from_topo)) + \
               (u'[User to=%d from=%d]' % (self.num_pkts_to_client, self.num_pkts_from_client))

class SystemInfo(Model):
    name = CharField(max_length=128, unique=True)
    value = TextField()
