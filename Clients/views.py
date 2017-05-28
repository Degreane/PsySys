# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import pprint as pp
from django.shortcuts import render
from django.http import HttpResponse
from django.http import HttpResponseRedirect
from django.conf import settings
from models import user
from urlparse import parse_qs

from hashlib import md5
from Crypto.Hash import MD5
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode,b64decode

import tempfile as tf

def derive_key_and_iv(password, salt, key_length, iv_length):
    d = d_i = ''
    while len(d) < key_length + iv_length:
        d_i = md5(d_i + password + salt).digest()
        d += d_i
    return d[:key_length], d[key_length:key_length+iv_length]

def encrypt(data, password, key_length=32):
    bs = AES.block_size
    salt = Random.new().read(bs - len('Salted__'))
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ch1='Salted__' + salt
    #print ch1
    if len(data) == 0 or len(data) % bs != 0:
        padding_length = bs - (len(data) % bs)
        data += padding_length * chr(padding_length)
    return ch1+cipher.encrypt(data)

def decrypt(data,  password, key_length=32):
    bs = AES.block_size
    salt = data[:bs][len('Salted__'):]
    #print len(salt)
    key, iv = derive_key_and_iv(password, salt, key_length, bs)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    chunk=data[bs:]
    unpadded_text=cipher.decrypt(chunk)
    padding_length=ord(unpadded_text[-1])
    #print ("padding Length {}".format(padding_length))
    padded_text=unpadded_text[:-padding_length]
    return padded_text



# Create your views here.
def index(request):
    #return HttpResponse("SomeThing requested {} to be sent back ".format(request))
    print("############ R! ###############")
    pp.pprint(request.session.__dict__)
    #pp.pprint(request.session.get('LoggedIn'))
    reqSessionID=request.session.session_key
    encKey=MD5.new(reqSessionID).hexdigest()
    thePath=request.__dict__['path']
    if thePath=='/id/index.html':
        # if this is the path then we assume here we are initializing login/logout so we check 
        #pp.pprint(request.__dict__)
        reqQueryString=parse_qs(request.GET.urlencode())
        #print(parse_qs(reqQueryString))
        #print("QueryString is {}".format(reqQueryString))
        # Now since we got the QueryString We check Existance of ver which should contain previous lgnName/lgnPass conducted here within.
        if reqQueryString.has_key('ver'):
            # Now We have the QueryString key and thus we validate the decrypted with the database from Model User
            pp.pprint(reqQueryString['ver'][0])
            print "The reqSessionID is {} = {}".format(reqSessionID,encKey)
            decryptedValues=decrypt(b64decode(reqQueryString['ver'][0]),encKey)
            pp.pprint(decryptedValues)
    
    print("############ R2 ###############")
    request.session.set_expiry(300)
    if request.session.has_key('LoggedIn'):
        clients = user.objects(isClient=True)
        return render(request,'index.html',{"tpls":clients})
    else :
        #request.session['LoggedIn']=True
        
        request.session["t"]=request.session.session_key
        request.session.save()
        pp.pprint("Session Keys after T is {}".format(request.session.__dict__))
        return HttpResponseRedirect('/login.sys')
