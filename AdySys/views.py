# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.conf import settings
import pprint as pp
# Create your views here.
def index(request):
    #return HttpResponse("SomeThing requested {} to be sent back ".format(request))
    #pp.pprint("Session Keys after Redirect T is {}".format(request.session.__dict__))
    #pp.pprint(request.session.keys())
    #print(request.session["t"])
    #print("###############<<>>################")
    return render(request,'login.html')