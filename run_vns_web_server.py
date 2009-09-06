from os import environ, path
import sys

from django.core.handlers.wsgi import WSGIHandler
from twisted.application import internet, service
from twisted.web import server, resource, wsgi, static
from twisted.python import threadpool
from twisted.internet import reactor

PORT = 80

# tell python about the VNS Django project
vns_root_dir = path.join(path.dirname(__file__), '').replace('\\','/')
sys.path.append(vns_root_dir)

# tell Django about the settings file
environ['DJANGO_SETTINGS_MODULE'] = 'web.settings'

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
