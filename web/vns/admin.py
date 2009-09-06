from django.contrib import admin
from web.vns.models import Simulator, Organization, UserProfile, \
                           TopologyTemplate, Node, Port, Link,   \
                           Topology, TopologyUser, IPAssignment, IPBlock

def make_user_search_fields(prefix):
    return (prefix + '__username', prefix + '__first_name', prefix + '__last_name')

class SimulatorAdmin(admin.ModelAdmin):
    list_display = ('name', 'ip')
    ordering = ('name',)
    search_fields = ('name', 'ip')

class OrganizationAdmin(admin.ModelAdmin):
    list_display = ('name', 'parentOrg', 'boss')
    ordering = ('name',)
    raw_id_fields = ('admins',)
    search_fields = ('name', 'parentOrg__name') + make_user_search_fields('boss')

class UserProfileAdmin(admin.ModelAdmin):
    list_display = ('user', 'org', 'pos')
    ordering = ('user',)
    search_fields = make_user_search_fields('user') + ('org__name', 'pos__name')

class TopologyTemplateAdmin(admin.ModelAdmin):
    list_display = ('name', 'org', 'owner', 'visibility', 'date_updated')
    ordering = ('name',)
    search_fields = make_user_search_fields('owner') + ('name', 'org__name', 'date_updated')

class NodeAdmin(admin.ModelAdmin):
    list_display = ('template', 'name', 'type')
    ordering = ('template', 'name')
    search_fields = ('template__name', 'name', 'type__name')

class PortAdmin(admin.ModelAdmin):
    list_display = ('node', 'name')
    ordering = ('node', 'name')
    search_fields = ('node__template__name', 'node__name', 'name')

class LinkAdmin(admin.ModelAdmin):
    list_display = ('port1', 'port2', 'lossiness')
    ordering = ('port1',)
    search_fields = ('port1__node__template__name', 'port1__node__name',
                     'port2__node__name', 'lossiness')

class TopologyAdmin(admin.ModelAdmin):
    list_display = ('node1', 'node2', 'lossiness')
    ordering = ('node1',)
    search_fields = ('node1__template__name', 'node1__name', 'node2__name', 'lossiness')

class TopologyAdmin(admin.ModelAdmin):
    list_display = ('owner', 'id', 'template')
    ordering = ('owner', 'id')
    search_fields = ('id', 'owner__name', 'template__name')

class TopologyUserAdmin(admin.ModelAdmin):
    list_display = ('topology', 'ip')
    ordering = ('ip',)
    search_fields = ('ip', 'topology__template__name', 'topology__name')

class IPAssignmentAdmin(admin.ModelAdmin):
    list_display = ('topology', 'port', 'ip', 'mask')
    ordering = ('ip',)
    search_fields = ('ip', 'topology__template__name', 'topology__name', 'port__node__name')

class IPBlockAdmin(admin.ModelAdmin):
    list_display = ('simulator', 'parentIPBlock', 'org', 'subnet', 'mask')
    ordering = ('subnet', 'mask')
    search_fields = ('simulator__name', 'org__name', 'subnet', 'mask')

admin.site.register(Simulator, SimulatorAdmin)
admin.site.register(Organization, OrganizationAdmin)
admin.site.register(UserProfile, UserProfileAdmin)
admin.site.register(TopologyTemplate, TopologyTemplateAdmin)
admin.site.register(Node, NodeAdmin)
admin.site.register(Port, PortAdmin)
admin.site.register(Link, LinkAdmin)
admin.site.register(Topology, TopologyAdmin)
admin.site.register(TopologyUser, TopologyUserAdmin)
admin.site.register(IPAssignment, IPAssignmentAdmin)
admin.site.register(IPBlock, IPBlockAdmin)
