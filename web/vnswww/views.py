from socket import inet_ntoa
import struct

from django.http import Http404, HttpResponse

import models as db
from vns.Topology import Topology

def invalid_topo_number_response(tid):
    body = """<html>
    <head><title>Topology not found</title></head>
    <body>Error: topology %d does not exist.</body>
</html>""" % tid
    return HttpResponse(body, mimetype='text/html')

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
