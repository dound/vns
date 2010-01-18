from socket import inet_ntoa
import struct

from django import forms
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.http import Http404, HttpResponse, HttpResponseRedirect
from django.shortcuts import render_to_response

import models as db
from vns.Topology import Topology
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

def create_topologies(request):
    # make sure the user is logged in
    if not request.user.is_authenticated():
        return HttpResponseRedirect('/login/?next=/create_topologies/')

    tn = 'vns/create_topologies.html'
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
                return render_to_response(tn, { 'form': form, 'more_error': 'invalid template' })

            try:
                ipblock = db.IPBlock.objects.get(pk=ipblock_id)
            except db.IPBlock.DoesNotExist:
                return render_to_response(tn, { 'form': form, 'more_error': 'invalid IP block' })

            if num_to_create > 30:
                return render_to_response(tn, { 'form': form, 'more_error': 'you cannot create >30 topologies at once' })

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
                    return render_to_response(tn)
            messages.success(request, "Successfully allocated %d '%s' topologies from %s." % (num_to_create, template.name, ipblock))
            return render_to_response(tn)
    else:
        form = CTForm()

    return render_to_response(tn, { 'form': form })

def invalid_topo_number_response(tid):
    body = """<html>
    <head><title>Topology not found</title></head>
    <body>Error: topology %d does not exist.</body>
</html>""" % tid
    return HttpResponse(body, mimetype='text/html')

def topology_delete(request, tid):
    tid = int(tid)
    try:
        topo = db.Topology.objects.get(pk=tid)
        if topo.owner == request.user:
            topo.delete()
            messages.success(request, 'Topology %d has been deleted.' % tid)
            return HttpResponseRedirect('/topologies/')
        else:
            messages.error(request, 'Topology %d is not yours to delete.' % tid)
            return HttpResponseRedirect('/topologies/')
    except db.Topology.DoesNotExist:
        return invalid_topo_number_response(tid)

def topology_readme(request, tid):
    tid = int(tid)
    try:
        topo = db.Topology.objects.get(pk=tid)
        return HttpResponse(topo.get_readme(), mimetype='text/plain')
    except db.Topology.DoesNotExist:
        return invalid_topo_number_response(tid)

def topology_to_xml(request, tid):
    tid = int(tid)
    try:
        topo = Topology(tid, None, None, None, start_stats=False)

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
    except db.Topology.DoesNotExist:
        return invalid_topo_number_response(tid)
