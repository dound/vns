from django.http import HttpResponseRedirect

def homepage(request):
    return HttpResponseRedirect('/summary/')
