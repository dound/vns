from django.http import HttpResponseRedirect
from django.views.generic.simple import direct_to_template

def checked_delete(request, delete_hook, kind, what, **kwargs):
    if request.method == 'POST':
        return delete_hook(request, **kwargs)
    else:
        c = { 'kind':kind, 'what':what }
        return direct_to_template(request, 'vns/delete_check.html', c)

def homepage(request):
    return HttpResponseRedirect('/summary/')
