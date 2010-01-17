from django.contrib import admin
from models import Simulator, Organization, UserProfile, StatsTopology, \
                   TopologyTemplate, Node, WebServer, WebServerHostname, Port, Link, \
                   Topology, TopologySourceIPFilter, TopologyUserFilter, \
                   IPAssignment, MACAssignment, IPBlock, IPBlockAllocation, \
                   RecentIPBlockAllocation, SystemInfo

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

class WebServerAdmin(admin.ModelAdmin):
    list_display = ('template', 'name', 'type', 'web_server_addr', 'replace_hostname_in_http_replies')
    ordering = ('template', 'name')
    search_fields = ('template__name', 'name', 'type__name', 'web_server_addr')

class WebServerHostnameAdmin(admin.ModelAdmin):
    list_display = ('hostname',)
    ordering = ('hostname',)
    search_fields = ('hostname',)

class PortAdmin(admin.ModelAdmin):
    list_display = ('node', 'name', 'ip_offset')
    ordering = ('node', 'name')
    search_fields = ('node__template__name', 'node__name', 'name')

class LinkAdmin(admin.ModelAdmin):
    list_display = ('port1', 'port2', 'lossiness')
    ordering = ('port1',)
    search_fields = ('port1__node__template__name', 'port1__node__name',
                     'port2__node__name', 'lossiness')

class TopologyAdmin(admin.ModelAdmin):
    list_display = ('owner', 'id', 'template', 'enabled', 'public', 'temporary')
    ordering = ('owner', 'id')
    search_fields = ('id', 'owner__name', 'template__name')

class TopologySourceIPFilterAdmin(admin.ModelAdmin):
    list_display = ('topology', 'ip')
    ordering = ('ip',)
    search_fields = ('ip', 'topology__template__name', 'topology__name')

class TopologyUserFilterAdmin(admin.ModelAdmin):
    list_display = ('topology', 'user')
    ordering = ('topology',)
    search_fields = ('user__username', 'topology__template__name', 'topology__name')

class IPAssignmentAdmin(admin.ModelAdmin):
    list_display = ('topology', 'port', 'ip', 'mask')
    ordering = ('topology__owner', 'topology', 'ip')
    search_fields = ('ip', 'topology__template__name', 'topology__name', 'port__node__name')

class MACAssignmentAdmin(admin.ModelAdmin):
    list_display = ('topology', 'port', 'mac')
    ordering = ('topology__owner', 'topology', 'mac')
    search_fields = ('mac', 'topology__template__name', 'topology__name', 'port__node__name')

class IPBlockAdmin(admin.ModelAdmin):
    list_display = ('simulator', 'parentIPBlock', 'org', 'subnet', 'mask', 'usable_by_child_orgs')
    ordering = ('subnet', 'mask')
    search_fields = ('simulator__name', 'org__name', 'subnet', 'mask')

class IPBlockAllocationAdmin(admin.ModelAdmin):
    list_display = ('block_from', 'topology', 'start_addr', 'mask')
    ordering = ('start_addr',)
    search_fields = ('block_from__org__name', 'topology__id', 'start_addr')

class RecentIPBlockAllocationAdmin(admin.ModelAdmin):
    list_display = ('user', 'template', 'start_addr', 'mask')
    ordering = ('user', 'template')
    search_fields = ('user.username', 'template.name', 'start_addr')

class StatsTopologyAdmin(admin.ModelAdmin):
    list_display = ('template', 'username', 'client_ip', 'time_connected', 'total_time_connected_sec', 'num_pkts_to_topo', 'num_pkts_from_topo', 'num_pkts_to_client', 'num_pkts_from_client', 'active')
    ordering = ('time_connected',)
    search_fields = ('template__name', 'username', 'client_ip')

class SystemInfoAdmin(admin.ModelAdmin):
    list_display = ('name', 'value')
    ordering = ('name',)
    search_fields = ('name', 'value')

admin.site.register(Simulator, SimulatorAdmin)
admin.site.register(Organization, OrganizationAdmin)
admin.site.register(UserProfile, UserProfileAdmin)
admin.site.register(TopologyTemplate, TopologyTemplateAdmin)
admin.site.register(Node, NodeAdmin)
admin.site.register(WebServer, WebServerAdmin)
admin.site.register(WebServerHostname, WebServerHostnameAdmin)
admin.site.register(Port, PortAdmin)
admin.site.register(Link, LinkAdmin)
admin.site.register(Topology, TopologyAdmin)
admin.site.register(TopologySourceIPFilter, TopologySourceIPFilterAdmin)
admin.site.register(TopologyUserFilter, TopologyUserFilterAdmin)
admin.site.register(IPAssignment, IPAssignmentAdmin)
admin.site.register(MACAssignment, MACAssignmentAdmin)
admin.site.register(IPBlock, IPBlockAdmin)
admin.site.register(IPBlockAllocation, IPBlockAllocationAdmin)
admin.site.register(RecentIPBlockAllocation, RecentIPBlockAllocationAdmin)
admin.site.register(StatsTopology, StatsTopologyAdmin)
admin.site.register(SystemInfo, SystemInfoAdmin)
