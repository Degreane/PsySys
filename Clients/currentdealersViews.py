from __future__ import unicode_literals

from django.shortcuts import render
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.conf import settings

from models import user
from mongoengine.queryset import Q
import json
from urlparse import parse_qs

from Crypto.Hash import MD5
from base64 import b64encode,b64decode

from MyCrypt import myCrypt

import tempfile as tf
import pprint as pp
def index(request):
	
	#Check if the Session has a LoggedIn value 
	if request.session.has_key('LoggedIn'):
		# Get The Session ID
		reqSessionID=request.session.session_key
		# Get the user from the session[theUserID]
		theUserID=request.session['theUserID']
		userQuery=Q(id=theUserID)
		theUser=user.objects(userQuery)
		if theUser.count() == 0 :
			return HttpResponseRedirect('/')
		else:
			'''print('Dealers Views')
			pp.pprint(theUser[0].firstName)
			pp.pprint(theUser[0].lastName)'''
			return render(request,'dealer_index.html',{'theUser':theUser[0]})
		#return HttpResponse('<br>'.join(request.__dict__))
	else:
		return HttpResponseRedirect('/')