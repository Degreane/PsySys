# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.conf import settings
# Create your views here.
def index(request):
    #return HttpResponse("SomeThing requested {} to be sent back ".format(request))
    return render(request,'login.html')