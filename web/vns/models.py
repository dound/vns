from django.db.models import AutoField, CharField, DateField, FloatField, ForeignKey, \
                             IntegerField, IPAddressField, ManyToManyField, Model
from django.contrib.auth.models import User

class Simulator(Model):
    """A VNS simulation server."""
    name = CharField(max_length=30, unique=True)
    ip = IPAddressField(unique=True,
                        help_text='IP address where the server is located.')

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

class Position(Model):
    """A user's role (in the VNS web system)."""
    name = CharField(max_length=30, unique=True)

    def __unicode__(self):
        return u'%s' % self.name

class UserProfile(Model):
    """Defines extra information to associate with a User."""
    user = ForeignKey(User, unique=True)
    org  = ForeignKey(Organization)
    pos  = ForeignKey(Position)

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

class NodeType(Model):
    """Describes a type of Node which can be simulated in a topology."""
    name = CharField(max_length=30, unique=True)

    def __unicode__(self):
        return u'%s' % self.name

class Node(Model):
    """A node in a topology template."""
    template = ForeignKey(TopologyTemplate)
    name = CharField(max_length=30)
    type = ForeignKey(NodeType)

    def __unicode__(self):
        return u'%s: %s' % (self.template.name, self.name)

class Port(Model):
    """A port on a node in a topology template."""
    node = ForeignKey(Node)
    name = CharField(max_length=5)

    def __unicode__(self):
        return u'%s: %s: %s' % (self.node.template.name, self.node.name, self.name)

class Link(Model):
    """A link connecting two nodes in a topology template."""
    port1 = ForeignKey(Node, related_name='port1_id')
    port2 = ForeignKey(Node, related_name='port2_id')
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

    def __unicode__(self):
        return u'Topology %d' % self.id

class TopologyUser(Model):
    """Lists the IP addresses which may interact with a topology through the
    simulator.  If no IPs are listed, then there will be no restrictions.  This
    is most useful for enabling different topologies to share (reuse) simulator
    IPs."""
    topology = ForeignKey(Topology)
    ip = IPAddressField()

    def __unicode__(self):
        return u'%s may interact with %s' % (self.ip, self.topology.__unicode__())

class IPAssignment(Model):
    """Maps an IP address to a node in a particular topology.  IPs may be
    assigned to more than one node based on constraints enforced at a higher
    level."""
    topology = ForeignKey(Topology)
    node = ForeignKey(Node)
    ip = IPAddressField()

    def __unicode__(self):
        return u'%s: %s <== %s' % (self.topology.__unicode__(), self.node.name, self.ip)

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
