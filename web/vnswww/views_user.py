from django import forms
from django.contrib import messages
from django.contrib.auth.models import User
from django.views.generic.simple import direct_to_template
from django.http import HttpResponseRedirect

import models as db

def user_access_check(request, callee, requester_is_staff_req, requester_in_same_org_req, self_req, **kwargs):
    """This wrapper function checks to make sure that a user exists if 'un' is
    one of the kwargs keys.  It also verifies the requester is logged in, etc.
    requester_is_staff_req requires that the request.user be a staff member.
    requester_in_same_org_req requires that the requester be in the same
    organization as the user specified by kwargs['un'].
    self_req requires that the requester match the user specified with kwargs.
    If these tests pass, callee is called with (request, **kwargs)."""
    # make sure the user is logged in
    if not request.user.is_authenticated():
        messages.warn(request, 'You must login before proceeding.')
        return HttpResponseRedirect('/login/?next=%s' % request.path)

    up = None
    try:
        un = kwargs['un']
        try:
            up = db.UserProfile.objects.get(user__username=un)
            kwargs['up'] = up
            del kwargs['un']
        except db.UserProfile.DoesNotExist:
            messages.error(request, "There is no user '%s'." % un)
            return HttpResponseRedirect('/')
    except KeyError:
        pass

    # make sure the requester is the boss of their own organization if required
    if requester_is_staff_req and not request.user.get_profile().is_staff():
            messages.error(request, "Only staff members may do that.")
            return HttpResponseRedirect('/')

    # make sure the requester is in the same organization as the user in question if required
    if requester_in_same_org_req:
        if not up:
            messages.error(request, "No user was specified (internal error?).")
            return HttpResponseRedirect('/')
        elif not request.user.is_superuser() and not request.user.org==up.org:
            messages.error(request, "Only staff in %s may do that." % up.org.name)
            return HttpResponseRedirect('/')

    # make sure the requester is up him/herself if required
    if self_req and request.user != up.user:
        messages.error(request, 'Only %s may do that.' % un)
        return HttpResponseRedirect('/')

    kwargs['request'] = request
    return callee(**kwargs)

class RegistrationForm(forms.Form):
    username   = forms.CharField(label='Username', max_length=30)
    first_name = forms.CharField(label='First Name', max_length=30)
    last_name  = forms.CharField(label='Last Name', max_length=30)
    email      = forms.CharField(label='E-mail Address', max_length=75)
    pw         = forms.CharField('Password', widget=forms.PasswordInput(render_value=False))
    pos        = forms.ChoiceField(label='Position', choices=[(1, u'Student'), (4, u'TA')])

def user_create(request):
    tn = 'vns/user_create.html'
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            email = form.cleaned_data['email']
            pw = form.cleaned_data['pw']
            pos = form.cleaned_data['pos']

            user = User.objects.create_user(username, email, pw)
            user.last_name = last_name
            user.first_name = first_name
            user.save()

            up = db.UserProfile()
            up.user = user
            up.pos = pos
            up.org = request.user.get_profile().org
            up.generate_and_set_new_sim_auth_key()
            up.save()

            messages.success(request, "Successfully created new user: %s" % username)
            return direct_to_template(request, tn)
    else:
        form = RegistrationForm()

    return direct_to_template(request, tn, { 'form': form })
