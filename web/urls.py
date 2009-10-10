from django.conf.urls.defaults import *
from django.contrib import admin
from django.views.generic import list_detail
from django.views.generic.simple import direct_to_template

from vnswww import models as db

admin.autodiscover()

summary_info = {
    'queryset': db.StatsTopology.objects.filter(active=True).order_by('id'),
    'template_name': 'vns/current_usage.html',
    'template_object_name': 'stats'
}

urlpatterns = patterns('web.vnswww.views',
    (r'^admin/', include(admin.site.urls)),
    (r'^summary/?$', list_detail.object_list, summary_info),
    (r'^vns.css$', direct_to_template, {'mimetype':'text/css', 'template':'vns.css'}),
)
