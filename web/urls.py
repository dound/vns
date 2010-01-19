from django.conf.urls.defaults import *
from django.contrib import admin
from django.contrib.auth.decorators import login_required
from django.views.generic import list_detail
from django.views.generic.simple import direct_to_template

from vnswww import models as db
from vnswww.views import homepage
from vnswww.views_topology import *

admin.autodiscover()

summary_info = {
    'queryset': db.StatsTopology.objects.filter(active=True).order_by('id'),
    'template_name': 'vns/current_usage.html',
    'template_object_name': 'stats'
}

topologies_info = {
    'queryset': db.Topology.objects.filter(enabled=True).order_by('owner__userprofile__org__name', 'template__name', 'id'),
    'template_name': 'vns/topologies.html',
    'template_object_name': 'topos'
}

# dictionaries which specify access requirements for various topology views
def make_topology_access_check_dict(callee, owner_req=False, pu_req=False, login_req=True):
    return { 'callee':callee, 'login_req':login_req, 'owner_req':owner_req, 'pu_req':pu_req }
dict_topo_delete    = make_topology_access_check_dict(topology_delete, True)
dict_topo_info      = make_topology_access_check_dict(topology_info)
dict_topo_pua       = make_topology_access_check_dict(topology_permitted_user_add, True)
dict_topo_pur       = make_topology_access_check_dict(topology_permitted_user_remove, True)
dict_topo_readme    = make_topology_access_check_dict(topology_readme)
dict_topo_xml       = make_topology_access_check_dict(topology_to_xml)
dict_topo_xml_clack = make_topology_access_check_dict(topology_to_xml, login_req=False) # TODO: temporary so Clack can access the xml

@login_required
def limited_object_list(*args, **kwargs):
    return list_detail.object_list(*args, **kwargs)

urlpatterns = patterns('web.vnswww.views',
    (r'^admin/', include(admin.site.urls)),
    (r'^(home|index([.]...?.?.?)?)?/?$',                homepage),
    (r'^summary/?$',                                    list_detail.object_list, summary_info),
    (r'^vns.css$',                                      direct_to_template, {'mimetype':'text/css', 'template':'vns.css'}),

    (r'^topologies/?$',                                 limited_object_list, topologies_info),
    (r'^topology(?P<tid>\d+)/?$',                       topology_access_check, dict_topo_info),
    (r'^topology/create/?$',                            topology_create),
    (r'^topology(?P<tid>\d+)/allow_new_user/?$',        topology_access_check, dict_topo_pua),
    (r'^topology(?P<tid>\d+)/disallow_user/(?P<un>\w+)$', topology_access_check, dict_topo_pur),
    (r'^topology(?P<tid>\d+)/delete/?$',                topology_access_check, dict_topo_delete),
    (r'^topology(?P<tid>\d+)/readme/?$',                topology_access_check, dict_topo_readme),
    (r'^topology(?P<tid>\d+)/xml/?$',                   topology_access_check, dict_topo_xml),
    (r'^topology=(?P<tid>\d+)$',                        topology_access_check, dict_topo_xml_clack), # old URL for Clack

)
urlpatterns += patterns('',
    (r'^login/?$', 'django.contrib.auth.views.login', {'template_name': 'vns/login.html'}),
    (r'^logout/?$', 'django.contrib.auth.views.logout', {'template_name': 'vns/logout.html'}),
)
