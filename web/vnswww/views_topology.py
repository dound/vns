from socket import inet_ntoa
import struct

from django import forms
from django.contrib import messages
from django.views.generic.simple import direct_to_template
from django.http import HttpResponse, HttpResponseRedirect

import models as db
from vns.AddressAllocation import instantiate_template

def make_ctform(user):
    user_org = user.get_profile().org
    parent_org = user_org.parentOrg
    template_choices = [(t.id, t.name) for t in db.TopologyTemplate.objects.filter(visibility=2)]
    ipblock_choices = [(t.id, str(t)) for t in db.IPBlock.objects.filter(org=user_org)] + \
                      [(t.id, str(t)) for t in db.IPBlock.objects.filter(org=parent_org, usable_by_child_orgs=True)]
    class CTForm(forms.Form):
        template = forms.ChoiceField(label='Template', choices=template_choices)
        ipblock = forms.ChoiceField(label='IP Block to Allocate From', choices=ipblock_choices)
        num_to_create = forms.IntegerField(label='# to Create', initial='1')
    return CTForm

def topology_create(request):
    # make sure the user is logged in
    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login/?next=/topology/create/')

    tn = 'vns/topology_create.html'
    CTForm = make_ctform(request.user)
    if request.method == 'POST':
        form = CTForm(request.POST)
        if form.is_valid():
            template_id = form.cleaned_data['template']
            ipblock_id = form.cleaned_data['ipblock']
            num_to_create = form.cleaned_data['num_to_create']

            try:
                template = db.TopologyTemplate.objects.get(pk=template_id)
            except db.TopologyTemplate.DoesNotExist:
                return direct_to_template(request, tn, { 'form': form, 'more_error': 'invalid template' })

            try:
                ipblock = db.IPBlock.objects.get(pk=ipblock_id)
            except db.IPBlock.DoesNotExist:
                return direct_to_template(request, tn, { 'form': form, 'more_error': 'invalid IP block' })

            if num_to_create > 30:
                return direct_to_template(request, tn, { 'form': form, 'more_error': 'you cannot create >30 topologies at once' })

            # TODO: should validate that request.user can use the requested
            #       template and IP block

            # try to create the topologies
            src_filters = []
            for i in range(num_to_create):
                err, _, _, _ = instantiate_template(request.user, template, ipblock, src_filters,
                                                    temporary=False,
                                                    use_recent_alloc_logic=False,
                                                    public=True,
                                                    use_first_available=True)
                if err is not None:
                    messages.error(request, "Successfully allocated %d '%s' topologies from %s.  Failed to make the other request topologies: %s." % (i, template.name, ipblock, err))
                    return direct_to_template(request, tn)
            messages.success(request, "Successfully allocated %d '%s' topologies from %s." % (num_to_create, template.name, ipblock))
            return direct_to_template(request, tn)
    else:
        form = CTForm()

    return direct_to_template(request, tn, { 'form': form })

def topology_access_check(request, callee, login_req, owner_req, pu_req,
                          var_tid='tid', **kwargs):
    """This wrapper function checks to make sure that a topology exists.  It
    also verifies the user is logged in, is the owner, or is a permitted user
    as dictated by the boolean arguments *_req.  If these tests pass, callee is
    called with (request, tid, topo)."""
    tid = int(kwargs[var_tid])
    try:
        topo = db.Topology.objects.get(pk=tid)
    except db.Topology.DoesNotExist:
        messages.error(request, 'Topology %d does not exist.' % tid)
        return HttpResponseRedirect('/topologies/')

    # make sure the user is logged in if required
    if login_req and not request.user.is_authenticated():
        messages.warn(request, 'You must login before proceeding.')
        return HttpResponseRedirect('/login/?next=%s' % request.path)

    # make sure the user is the owner if required
    if owner_req and request.user != topo.owner:
        messages.error(request, 'Only the owner (%s) can do this.' % topo.owner.username)
        return HttpResponseRedirect('/topology%d/' % tid)

    # make sure the user is a permitted user if required
    if (not owner_req and pu_req) and request.user != topo.owner:
        try:
            db.TopologyUserFilter.objects.get(topology=topo, user=request.user)
        except db.TopologyUserFilter.DoesNotExist:
            messages.error(request, 'Only the owner (%s) or permitted users can do this.' % topo.owner.username)
            return HttpResponseRedirect('/topology%d/' % tid)

    kwargs['request'] = request
    kwargs['tid'] = tid
    kwargs['topo'] = topo
    return callee(**kwargs)

def topology_info(request, tid, topo):
    return direct_to_template(request, 'vns/topology.html', {'t':topo, 'tid':tid})

def make_apu_form(user, topo):
    user_org = user.get_profile().org
    existing_tuf_users = [tuf.user for tuf in db.TopologyUserFilter.objects.filter(topology=topo)]
    user_choices = [(up.user.username,up.user.username) for up in db.UserProfile.objects.filter(org=user_org).exclude(user=user).exclude(user__in=existing_tuf_users)]

    class APUForm(forms.Form):
        usr = forms.ChoiceField(label='User', choices=user_choices)
    return APUForm

def topology_permitted_user_add(request, tid, topo):
    tn = 'vns/topology_add_permitted_user.html'
    APUForm = make_apu_form(request.user, topo)
    if request.method == 'POST':
        form = APUForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['usr']

            try:
                user = db.UserProfile.objects.get(user__username=username).user
            except db.UserProfile.DoesNotExist:
                return direct_to_template(request, tn, {'form':form, 'more_error':'invalid username', 'tid':tid})

            if topo.owner == user:
                messages.error(request, 'This topology is already owned by %s.' % username)
                return HttpResponseRedirect('/topology%d/' % tid)

            tuf = db.TopologyUserFilter()
            tuf.topology = topo
            tuf.user = user
            tuf.save()
            messages.success(request, "%s (%s) has been added to the permitted users list." % (username, user.get_full_name()))
            return HttpResponseRedirect('/topology%d/' % tid)
    else:
        form = APUForm()
    return direct_to_template(request, tn, {'form':form, 'tid':tid })

def topology_permitted_user_remove(request, tid, topo, un):
    try:
        db.TopologyUserFilter.objects.get(topology=topo, user__username=un).delete()
        messages.success(request, "%s is no longer a permitted user on this topology." % un)
    except db.TopologyUserFilter.DoesNotExist:
        messages.error(request, "%s isn't a permitted user on this topology anyway." % un)
    return HttpResponseRedirect('/topology%d/' % tid)

def topology_delete(request, tid, topo, **kwargs):
    topo.delete()
    messages.success(request, 'Topology %d has been deleted.' % tid)
    return HttpResponseRedirect('/topologies/')

def topology_readme(request, tid, topo):
    return HttpResponse(topo.get_readme(), mimetype='text/plain')

def topology_to_xml(request, tid, topo):
    # populate xml IDs
    id = 1
    for node in topo.nodes:
        for intf in node.interfaces:
            intf.xml_id = id
            id += 1

    # build XML for nodes
    nodes_xml = ''
    for node in topo.nodes:
        for intf in node.interfaces:
            if intf.link:
                intf.neighbors = [str(intf.link.get_other(intf).xml_id)]
            else:
                intf.neighbors = []

        virtual = node.get_type_str() == 'Virtual Node'
        xml_hdr = '<host name="%s" offlimits="%d">\n' % (node.name, not virtual)
        xml_body = ''
        itag = ('v' if virtual else 'e') + 'interface'
        for intf in node.interfaces:
            xml_body += '<%s id="%d" name="%s" neighbors="%s" ip="%s" mask="%s" addr="%s"></%s>' % (
                        itag, intf.xml_id, intf.name, ','.join(intf.neighbors),
                        inet_ntoa(intf.ip), inet_ntoa(intf.mask),
                         ':'.join(['%02X' % struct.unpack('B', b)[0] for b in intf.mac]), itag)
        nodes_xml += xml_hdr + xml_body + '</host>\n'

    # build the topology's XML
    xml = '<topology id="%d">\n%s</topology>' % (topo.id, nodes_xml)
    return HttpResponse(xml, mimetype='text/xml')
