from django.conf.urls.defaults import *
from django.contrib import admin
from django.views.generic import list_detail
from django.views.generic.simple import direct_to_template, redirect_to

from vnswww import models as db
from vnswww.views import checked_delete, homepage
from vnswww.views_topology import *
from vnswww.views_user import *

admin.autodiscover()

summary_info = {
    'queryset': db.UsageStats.objects.filter(active=True).order_by('id'),
    'template_name': 'vns/current_usage.html',
    'template_object_name': 'stats'
}

organizations_info = {
    'queryset': db.Organization.objects.exclude(name='Public').order_by('name'),
    'template_name': 'vns/organizations.html',
    'template_object_name': 'orgs'
}

# dictionaries which specify access requirements for various topology views
def make_topology_access_check_dict(callee, owner_req=False, pu_req=False, login_req=True):
    return { 'callee':callee, 'login_req':login_req, 'owner_req':owner_req, 'pu_req':pu_req }
dict_topo_delete    = make_topology_access_check_dict(checked_delete, True)
dict_topo_delete['delete_hook'] = topology_delete
dict_topo_delete['kind'] = 'Topology'
dict_topo_delete['var_tid'] = 'what'
dict_topo_list      = make_topology_access_check_dict(topologies_list)
dict_topo_info      = make_topology_access_check_dict(topology_info)
dict_topo_pua       = make_topology_access_check_dict(topology_permitted_user_add, True)
dict_topo_pur       = make_topology_access_check_dict(topology_permitted_user_remove, True)
dict_topo_psipa     = make_topology_access_check_dict(topology_permitted_sip_add, True)
dict_topo_psipr     = make_topology_access_check_dict(topology_permitted_sip_remove, True)
dict_topo_readme    = make_topology_access_check_dict(topology_readme)
dict_topo_rtable    = make_topology_access_check_dict(topology_rtable)
dict_topo_xml       = make_topology_access_check_dict(topology_to_xml)
dict_topo_xml_clack = make_topology_access_check_dict(topology_to_xml, login_req=False) # TODO: temporary so Clack can access the xml

# dictionaries which specify access requirements for various user/org views
def make_user_access_check_dict(callee, requester_is_staff_req=False, requester_in_same_org_req=False, self_req=False, login_required=True):
    return { 'callee':callee, 'requester_is_staff_req':requester_is_staff_req, 'requester_in_same_org_req':requester_in_same_org_req, 'self_req':self_req, 'login_required':login_required }
dict_user_org       = make_user_access_check_dict(user_org, login_required=False)
dict_user_create    = make_user_access_check_dict(user_create, True)
dict_user_change_pw = make_user_access_check_dict(user_change_pw, self_req=True)
dict_user_delete    = make_user_access_check_dict(checked_delete, True, True)
dict_user_delete['delete_hook'] = user_delete
dict_user_delete['kind'] = 'User'
dict_user_delete['var_un'] = 'what'
dict_user_delete['del_un'] = False
dict_user_profile   = make_user_access_check_dict(user_profile)

def redirect_to_file(request, folder, file, ext):
    return redirect_to(request, folder + file + '.' + ext)

urlpatterns = patterns('web.vnswww.views',
    (r'^admin/', include(admin.site.urls)),
    (r'^$',                                             homepage),
    (r'^summary/?$',                                    list_detail.object_list, summary_info),
    (r'^vns[.]css$',                                    direct_to_template, {'mimetype':'text/css', 'template':'vns.css'}),

    # topology URLs
    (r'^topologies/?$',                                 topologies_list),
    (r'^topology(?P<tid>\d+)/?$',                       topology_access_check, dict_topo_info),
    (r'^topology/create/?$',                            topology_create),
    (r'^topology(?P<tid>\d+)/allow_new_user/?$',        topology_access_check, dict_topo_pua),
    (r'^topology(?P<tid>\d+)/disallow_user/(?P<un>\w+)/?$',    topology_access_check, dict_topo_pur),
    (r'^topology(?P<tid>\d+)/allow_new_srcip/?$',              topology_access_check, dict_topo_psipa),
    (r'^topology(?P<tid>\d+)/disallow_srcip/(?P<sn>[^/]+/\d+)/?$', topology_access_check, dict_topo_psipr),
    (r'^topology(?P<what>\d+)/delete/?$',               topology_access_check, dict_topo_delete),
    (r'^topology(?P<tid>\d+)/readme/?$',                topology_access_check, dict_topo_readme),
    (r'^topology(?P<tid>\d+)/rtable/?$',                topology_access_check, dict_topo_rtable),
    (r'^topology(?P<tid>\d+)/xml/?$',                   topology_access_check, dict_topo_xml),
    (r'^topology=(?P<tid>\d+)$',                        topology_access_check, dict_topo_xml_clack), # old URL for Clack

    # user / organization URLs
    (r'^organizations/?$',                              list_detail.object_list, organizations_info),
    (r'^org/(?P<on>[^/]+)/?$',                          user_access_check, dict_user_org),
    (r'^user/create/?$',                                user_access_check, dict_user_create),
    (r'^user/(?P<un>\w+)/change_password/?$',           user_access_check, dict_user_change_pw),
    (r'^user/(?P<what>\w+)/delete/?$',                  user_access_check, dict_user_delete),
    (r'^user/(?P<un>\w+)/?$',                           user_access_check, dict_user_profile),
)
urlpatterns += patterns('',
    (r'^favicon[.]ico$', redirect_to, {'url':'/media/favicon.ico'}),
    (r'^js/(?P<file>.*)[.]js$', redirect_to_file, {'folder':'/media/js/', 'ext':'js'}),
    (r'^login/?$', 'django.contrib.auth.views.login', {'template_name': 'vns/login.html'}),
    (r'^logout/?$', 'django.contrib.auth.views.logout', {'template_name': 'vns/logout.html'}),
)
