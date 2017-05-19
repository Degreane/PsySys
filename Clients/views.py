# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.conf import settings
from models import user
# Create your views here.
def index(request):
    #return HttpResponse("SomeThing requested {} to be sent back ".format(request))
    print request
    if request.session.has_key('LoggedIn'):
        clients = user.objects(isClient=True)
        return render(request,'index.html',{"tpls":clients})
    else :
        return HttpResponseRedirect('/login.sys')