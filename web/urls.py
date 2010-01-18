from django.conf.urls.defaults import *
from django.contrib import admin
from django.views.generic import list_detail
from django.views.generic.simple import direct_to_template

from vnswww import models as db
from vnswww.views import *

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

dict_topo_delete = {
    'callee': topology_delete,
    'owner_req': True
}
dict_topo_info = {
    'callee': topology_info,
}
dict_topo_pua = {
    'callee': topology_permitted_user_add,
    'owner_req': True
}
dict_topo_pur = {
    'callee': topology_permitted_user_remove,
    'owner_req': True
}
dict_topo_readme = {
    'callee': topology_readme
}
dict_topo_xml = {
    'callee': topology_to_xml,
}
dict_topo_xml_clack = {
    'callee': topology_to_xml,
    'login_req': False    # TODO: temporary so Clack can access the xml
}

urlpatterns = patterns('web.vnswww.views',
    (r'^admin/', include(admin.site.urls)),
    (r'^summary/?$',                                    list_detail.object_list, summary_info),

    (r'^topologies/?$',                                 list_detail.object_list, topologies_info),
    (r'^topology(?P<tid>\d+)/?$',                       topology_access_check, dict_topo_info),
    (r'^topology/create/?$',                            topology_create),
    (r'^topology(?P<tid>\d+)/add_permitted_user/?$',    topology_access_check, dict_topo_pua),
    (r'^topology(?P<tid>\d+)/remove_permitted_user/?$', topology_access_check, dict_topo_pur),
    (r'^topology(?P<tid>\d+)/delete/?$',                topology_access_check, dict_topo_delete),
    (r'^topology(?P<tid>\d+)/readme/?$',                topology_access_check, dict_topo_readme),
    (r'^topology(?P<tid>\d+)/xml/?$',                   topology_access_check, dict_topo_xml),
    (r'^topology=(?P<tid>\d+)$',                        topology_access_check, dict_topo_xml_clack), # old URL for Clack

    (r'^vns.css$', direct_to_template, {'mimetype':'text/css', 'template':'vns.css'}),
)
urlpatterns += patterns('',
    (r'^login/?$', 'django.contrib.auth.views.login', {'template_name': 'vns/login.html'}),
    (r'^logout/?$', 'django.contrib.auth.views.logout', {'template_name': 'vns/logout.html'}),
)
