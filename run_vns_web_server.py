import logging
from os import path
import re
import sys

from django.core.handlers.wsgi import WSGIHandler
from twisted.application import internet, service
from twisted.web import server, resource, wsgi, static
from twisted.python import threadpool
from twisted.internet import reactor
import twisted

# make sure we can find the settings and web modules (as well as the root vns module)
vns_root_dir = path.join(path.dirname(path.abspath(__file__)), '').replace('\\','/')
one_above_vns_root_dir = path.abspath(vns_root_dir + '/..')
sys.path.append(vns_root_dir)
sys.path.append(one_above_vns_root_dir)

# enable logging if we're in web DEBUG mode
from web.settings import DEBUG as VNSWWW_DEBUG
level = logging.DEBUG if VNSWWW_DEBUG else logging.WARN
logging.basicConfig(format='%(levelname)-8s %(funcName)s:%(lineno)d  %(message)s', level=level)

# this also sets the DJANGO_SETTINGS_MODULE environment variable
from settings import VNS_WEB_SERVER_PORT as PORT

# twisted version check
v = re.findall(r'^(\d+)\.(\d+)\.(\d+)([+]r(\d+))?', twisted.__version__)[0]
tmaj, tmin = int(v[0]), int(v[1])
if tmaj<8 or (tmaj==8 and tmin<2) or (tmaj==8 and tmin==2 and (v[4]=='' or int(v[4])<27292)):
    print >> sys.stderr, 'Fatal Error: twisted version 8.2.0+r27292 or higher is required!'
    sys.exit(-1)

def wsgi_resource():
    pool = threadpool.ThreadPool()
    pool.start()
    reactor.addSystemEventTrigger('after', 'shutdown', pool.stop)
    wsgi_resource = wsgi.WSGIResource(reactor, pool, WSGIHandler())
    return wsgi_resource

application = service.Application('twisted-django')

# WSGI container for Django, combine it with twisted.web.Resource:
class Root(resource.Resource):
    def __init__(self, wsgi_resource):
        resource.Resource.__init__(self)
        self.wsgi_resource = wsgi_resource

    def getChild(self, path, request):
        path0 = request.prepath.pop(0)
        request.postpath.insert(0, path0)
        return self.wsgi_resource

wsgi_root = wsgi_resource()
root = Root(wsgi_root)

# serve Django media files off of /media:
staticrsrc = static.File(path.join(path.abspath("."), "web/media"))
root.putChild("media", staticrsrc)

# serve the site
main_site = server.Site(root)
internet.TCPServer(PORT, main_site).setServiceParent(application)
