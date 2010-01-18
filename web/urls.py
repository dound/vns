from django.conf.urls.defaults import *
from django.contrib import admin
from django.views.generic import list_detail
from django.views.generic.simple import direct_to_template

from vnswww import models as db
from vnswww.views import create_topologies

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

urlpatterns = patterns('web.vnswww.views',
    (r'^admin/', include(admin.site.urls)),
    (r'^create_topologies/?$', create_topologies),
    (r'^summary/?$', list_detail.object_list, summary_info),
    (r'^topologies/?$', list_detail.object_list, topologies_info),
    (r'^topology(?P<tid>\d+)/delete$', 'topology_delete'),
    (r'^topology(?P<tid>\d+)/readme$', 'topology_readme'),
    (r'^topology(?P<tid>\d+)/xml$', 'topology_to_xml'),
    (r'^topology=(?P<tid>\d+)$', 'topology_to_xml'), # old URL for Clack
    (r'^vns.css$', direct_to_template, {'mimetype':'text/css', 'template':'vns.css'}),
)
urlpatterns += patterns('',
    (r'^login/?$', 'django.contrib.auth.views.login', {'template_name': 'vns/login.html'}),
    (r'^logout/?$', 'django.contrib.auth.views.logout', {'template_name': 'vns/logout.html'}),
)
