# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import pprint as pp
from django.shortcuts import render
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.conf import settings
from models import user
import json
from urlparse import parse_qs

from Crypto.Hash import MD5
from base64 import b64encode,b64decode

from MyCrypt import myCrypt

import tempfile as tf



# Create your views here.
def index(request):
    request.session.set_expiry(600)
    #return HttpResponse("SomeThing requested {} to be sent back ".format(request))
    print("############ R! ###############")
    reqSessionID=request.session.session_key
    encKey=MD5.new(reqSessionID).hexdigest()
    thePath=request.path
    if thePath=='/index.html':
        reqQueryString=str(request.META['QUERY_STRING'])
        reqQueryStringParse=parse_qs(reqQueryString)
        reqQueryStringKeys=reqQueryStringParse.keys()
        reqQueryStringParsed={}
        if len(reqQueryStringKeys) > 0 :
            # if the length is greater than zero then we have data collected in and passed in the URL
            for theKey in reqQueryStringKeys:
                # Here we have the Key we should take the character length of this key
                # then we add 1 to this key which should correspond to key=
                # then we check for the index of the whole key= in the string
                keyLen=len(theKey)+1
                keyIDX=reqQueryString.index(theKey)
                keyValueLen=len(reqQueryStringParse[theKey][0])
                keyValue=str(reqQueryString[keyIDX+keyLen:keyValueLen+keyLen]).encode('ascii','ignore')
                reqQueryStringParsed[theKey]=keyValue
        
        if reqQueryStringParsed.has_key('verdict'):
            # Now We have the QueryString key and thus we validate the decrypted with the database from Model User
            try:
                #decryptedValues=decrypt(b64decode(reqQueryStringParsed['verdict']),encKey)
                decryptedValues=myCrypt().decrypt(b64decode(reqQueryStringParsed['verdict']),encKey)
                # decryptedValues now contain a string which should be serialized into a lgnName/lgnPass
                # and get the Valid lgnUser denoting the current User logging In .
                
                decryptedValuesJson=parse_qs(decryptedValues)
                print "Loads >"
                print decryptedValues
                pp.pprint(decryptedValuesJson)
                print "Loads <"
                # Now We have The lgnName,lgnPass We should get the current document in the server.
                theUser=user.objects(lgnName=decryptedValuesJson['lgnName'][0],lgnPass=decryptedValuesJson['lgnPass'][0])
                if theUser.count() == 1:
                    print "Horray We have Record"
                    # we choose to get index Array[0] since the return of as_pymongo is an array of objects.
                    theUserDetailed=theUser[0]
                    pp.pprint(dir(theUserDetailed))
                    # Next we set our session['LoggedIn']= True
                    request.session['LoggedIn']=True
                    request.session['theUserID']=str(theUserDetailed.id)
                    request.session.save()
                    return render(request,'index.html',{'theUser':theUserDetailed})
            except Exception,e:
                pp.pprint(e)
                print "Due To The Error Above We are redirecting Back to Home Page"
                print "We are Removing the temporary key Value"
                #del request.session["t"]
                request.session.clear()
                request.session.flush()                
                return HttpResponseRedirect('/')
    
    print("############ R2 ###############")
    
    if request.session.has_key('LoggedIn'):
        theUserID=request.session['theUserID']
        theUser=user.objects(pk=theUserID)
        if theUser.count() == 1:
            theUserDetailed=theUser[0]
            #pp.pprint(theUserDetailed.__dict__)
            pp.pprint(theUser.to_json())
            # Next we set our session['LoggedIn']= True            
            return render(request,'index.html',{'theUser':theUserDetailed})
        else:
            del request.session['LoggedIn']
            return HttpResponseRedirect('/')
    else :
        #request.session['LoggedIn']=True
        print("Here We get The Redirection For Index Views ")
        if request.session.session_key == None :
            print("Here We get The Redirection For Index Views \n#########@@^^ Redirecting Back \n")
            return HttpResponseRedirect('/')
        pp.pprint(request.session.__dict__)
        request.session["t"]=request.session.session_key
        print(MD5.new(request.session["t"]).hexdigest(),"T according to MD5")
        request.session.save()
        pp.pprint("Session Keys after T is {}".format(request.session.__dict__))
        print("Here We get The Redirection For Index Views <----------- END")
        return HttpResponseRedirect('/login.sys')
