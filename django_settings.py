from os import environ, path
import sys

# tell python about the VNS Django project
vns_root_dir = path.join(path.dirname(__file__), '').replace('\\','/')
sys.path.append(vns_root_dir)

# tell Django about the settings file
environ['DJANGO_SETTINGS_MODULE'] = 'web.settings'

# location where the VNS web server will listen
VNS_WEB_SERVER_PORT = 80
