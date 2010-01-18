import os

DEBUG = TEMPLATE_DEBUG = False

ADMINS = (
    ('David Underhill', 'dgu@cs.stanford.edu'),
)

MANAGERS = ADMINS
PROJECT_PATH = os.path.abspath(os.path.dirname(__file__))

DATABASES = {
    'default': {
        'NAME': os.path.join(PROJECT_PATH, 'vns.db'),
        'ENGINE': 'sqlite3',
    }
}

TIME_ZONE = 'America/New_York'
LANGUAGE_CODE = 'en-us'
SITE_ID = 1
USE_I18N = False

# location of static media files
MEDIA_ROOT = ''
MEDIA_URL = '/media/'
ADMIN_MEDIA_PREFIX = '/media/admin/'

SECRET_KEY = 'this_key_is_only_for_testing_purposes'

TEMPLATE_LOADERS = (
    'django.template.loaders.filesystem.load_template_source',
    'django.template.loaders.app_directories.load_template_source',
)

MIDDLEWARE_CLASSES = (
    'django.middleware.common.CommonMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
)

TEMPLATE_CONTEXT_PROCESSORS = (
    'django.core.context_processors.auth',
    'django.contrib.messages.context_processors.messages',
)

ROOT_URLCONF = 'web.urls'

TEMPLATE_DIRS = (
     os.path.join(PROJECT_PATH, 'templates'),
)

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.messages',
    'django.contrib.sessions',
    'web.vnswww'
)

AUTH_PROFILE_MODULE = "vnswww.UserProfile"
LOGIN_REDIRECT_URL = '/topologies/'
LOGIN_URL = '/login/'
MESSAGE_STORAGE = 'django.contrib.messages.storage.cookie.CookieStorage'
