import re

from django import forms
from django.contrib import messages
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from django.views.generic.simple import direct_to_template
from django.http import HttpResponseRedirect

import models as db

def user_access_check(request, callee, requester_is_staff_req, requester_in_same_org_req, self_req, login_required,
                      var_un='un', del_un=True, **kwargs):
    """This wrapper function checks to make sure that a user exists if 'un' is
    one of the kwargs keys.  It also verifies the requester is logged in, etc.
    requester_is_staff_req requires that the request.user be a staff member.
    requester_in_same_org_req requires that the requester be in the same
    organization as the user specified by kwargs['un'].
    self_req requires that the requester match the user specified with kwargs or
    be on staff in the user's organization.
    If these tests pass, callee is called with (request, **kwargs)."""
    # make sure the user is logged in
    requester = request.user
    if login_required and not requester.is_authenticated():
        messages.warning(request, 'You must login before proceeding.')
        return HttpResponseRedirect('/login/?next=%s' % request.path)

    up = None
    try:
        un = kwargs[var_un]
        try:
            up = db.UserProfile.objects.get(user__username=un, retired=False)
            kwargs['up'] = up
            if del_un:
                del kwargs[var_un]
        except db.UserProfile.DoesNotExist:
            messages.error(request, "There is no user '%s'." % un)
            return HttpResponseRedirect('/')
    except KeyError:
        pass

    try:
        on = kwargs['on']
        try:
            org = db.Organization.objects.get(name=on)
            kwargs['org'] = org
            del kwargs['on']
        except db.Organization.DoesNotExist:
            messages.error(request, "There is no organization '%s'." % on)
            return HttpResponseRedirect('/')
    except KeyError:
        pass

    # make sure the requester is the boss of their own organization if required
    if requester_is_staff_req and not requester.get_profile().is_staff():
        messages.error(request, "Only staff members may do that.")
        return HttpResponseRedirect('/')

    # make sure we have up if it is needed
    if requester_in_same_org_req and not up:
        messages.error(request, "No user was specified (internal error?).")
        return HttpResponseRedirect('/')

    # make sure the requester is in the same organization as the user in question if required
    if requester_in_same_org_req:
        grp_txt = 'staff' if requester_is_staff_req else 'users'
        msg = "Only %s in %s may do that." % (grp_txt, up.org.name)
        if requester.is_superuser:
            messages.info(request, msg + "  However, so can you since you're a superuser.")
        elif not requester.get_profile().org==up.org:
            messages.error(request, msg)
            return HttpResponseRedirect('/')

    # make sure the requester is up him/herself if required
    if self_req and up and request.user != up.user:
        msg = 'Only %s or staff in his/her organization may do that.' % un
        if requester.is_superuser:
            messages.info(request, msg + "  However, so can you since you're a superuser.")
        elif not requester.get_profile().is_staff() or not requester.org==up.org:
            messages.error(request, msg)
            return HttpResponseRedirect('/')

    kwargs['request'] = request
    return callee(**kwargs)

def user_org(request, org):
    tn = 'vns/user_org.html'
    users = [u for u in db.UserProfile.objects.filter(org=org, retired=False)]
    users.sort(db.UserProfile.cmp_pos_order)
    return direct_to_template(request, tn, {'org':org, 'users':users})

class RegistrationForm(forms.Form):
    username   = forms.CharField(label='Username', max_length=30)
    first_name = forms.CharField(label='First Name', max_length=30)
    last_name  = forms.CharField(label='Last Name', max_length=30)
    email      = forms.CharField(label='E-mail Address', max_length=75)
    pw         = forms.CharField(label='Password', min_length=6, widget=forms.PasswordInput(render_value=False))
    pos        = forms.ChoiceField(label='Position', choices=[(1, u'Student'), (4, u'TA')])

    def clean_username(self):
        un = self.cleaned_data['username']
        if not re.match('^\w+$', un):
            raise forms.ValidationError("Only alphanumeric characters and spaces are allowed in a user's name.")
        return un

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
            return HttpResponseRedirect('/user/%s/' % username)
    else:
        form = RegistrationForm()
    return direct_to_template(request, tn, { 'form': form })

class AdminChangePasswordForm(forms.Form):
    new_pw1  = forms.CharField(label='New Password', min_length=6, widget=forms.PasswordInput(render_value=False))
    new_pw2  = forms.CharField(label='New Password (again)', widget=forms.PasswordInput(render_value=False))

class ChangePasswordForm(forms.Form):
    old_pw   = forms.CharField(label='Current Password', widget=forms.PasswordInput(render_value=False))
    new_pw1  = forms.CharField(label='New Password', min_length=6, widget=forms.PasswordInput(render_value=False))
    new_pw2  = forms.CharField(label='New Password (again)', widget=forms.PasswordInput(render_value=False))
    
def user_change_pw(request, up):
    tn = 'vns/user_change_pw.html'
    is_admin = up.user != request.user
    Form = AdminChangePasswordForm if is_admin else ChangePasswordForm
    if request.method == 'POST':
        form = Form(request.POST)
        if form.is_valid():
            if not is_admin:
                old_pw = form.cleaned_data['old_pw']
            new_pw1 = form.cleaned_data['new_pw1']
            new_pw2 = form.cleaned_data['new_pw2']

            if new_pw1 != new_pw2:
                messages.error(request, "Try again: the two versions of your new password do not match.")
                return direct_to_template(request, tn, { 'form': form, 'un':up.user.username })

            if not is_admin and not authenticate(username=up.user.username, password=old_pw):
                messages.error(request, "Incorrect current password.")
                return direct_to_template(request, tn, { 'form': form, 'un':up.user.username })

            up.user.set_password(new_pw1)
            up.user.save()

            if is_admin:
                messages.success(request, "You have successfully updated %s's password." % up.user.username)
            else:
                messages.success(request, "You have successfully updated your password.")
            return HttpResponseRedirect('/user/%s/' % up.user.username)
    else:
        form = Form()

    return direct_to_template(request, tn, { 'form': form, 'un':up.user.username })

def user_delete(request, up, **kwargs):
    user = up.user
    un = user.username
    on = up.org.name
    user.retired = True
    user.save()
    messages.success(request, "You have successfully deleted %s." % un)
    return HttpResponseRedirect('/org/%s/' % on)

def user_profile(request, up):
    tn = 'vns/user_profile.html'
    return direct_to_template(request, tn, {'up':up})
