from channels.auth import channel_session_user,channel_session_user_from_http,http_session
from channels.routing import route, route_class
from channels.sessions import channel_and_http_session,channel_session
import json
import pprint as pp
from django.http import HttpResponse
from django.http import HttpResponseRedirect

from Crypto.Hash import MD5
from hashlib import md5
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode,b64decode
from models import user

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


@channel_and_http_session
def connectedChannel(message):
	# We get this in here when we connect from a socket for login 
	print("Message Connected decrypting in Clients")
	encKey=MD5.new(str(message.reply_channel)).hexdigest()
	decryptedJSON=decrypt(b64decode(message['text']),encKey)
	print("\tEncKey is {}\n\tMessage is {}\n\tDecryptJson is {}\n".format(encKey,message['text'],decryptedJSON))
	messageJSON=json.loads(decryptedJSON)
	if messageJSON["target"] == 'login' and message.http_session.has_key('u'):
		Client = user.objects(lgnName=messageJSON['lgnName'],lgnPass=messageJSON['lgnPass'] )
		if Client.count() == 1:
			pp.pprint(Client.__dict__)
			#print "Client Accepted"
			#set redirect page
			# Note that this time the EncKey is the t taken from the http_session
			#pp.pprint(message.http_session.keys())
			SessEncKey=MD5.new(str(message.http_session['u'])).hexdigest()
			print(SessEncKey," Encrypted New Sess Key ")
			print("<-----------------^^^^------------------->")
				
			redirectPage="/index.html?lgnName={}&lgnPass={}".format(messageJSON['lgnName'],messageJSON['lgnPass'])
			encryptedRedirectPage=b64encode(encrypt(redirectPage,SessEncKey))
			print("\t#################\n\tRedirectPage is {}\n\tEncKey is {}\n".format(encryptedRedirectPage,SessEncKey))
			#print dir(message.http_session)
			#message.http_session={"LoggedIn":True}
			#print message.http_session.keys()
			message.reply_channel.send({
			        'text':json.dumps({'verdict':encryptedRedirectPage})
			})
			#message.http_session['LoggedInn']=True
			#message.http_session['LId']=

		else:
			#print "Client Not Accepted"
			redirectPage="False"
			encryptedRedirectPage=b64encode(encrypt(redirectPage,encKey))
			message.reply_channel.send({
			        'text':json.dumps({'verdict':encryptedRedirectPage})
			})			


@channel_and_http_session
def connectChannelid(message):
	#print("\n#####################\nGetting reply Channel ID {}\n###################\n".format(str(message.reply_channel)))
	#print("\n#####################\nGetting http session key {}\n###################\n".format(type(message.http_session)))
	#print("\n#####################\nGetting http session key {}\n###################\n".format(message.http_session.keys()))
	#print("\n#####################\nGetting http session key {}\n###################\n".format(str(message.http_session.session_key)))
	#print "in Clients Routing "
	#print message.__dict__
	message.reply_channel.send({'accept':True,
                                'text':json.dumps({'enc':MD5.new(str(message.reply_channel)).hexdigest()})
                                })
@channel_and_http_session
def processRequest(request):
	print("Processing Request ")
	pp.pprint(request.__dict__)
	pp.pprint(request.__dict__['http_session'])
	request.__dict__['http_session'].create()
	request.__dict__['http_session']['LoggedIn']=True
	#request.__dict__['http_session'].save(must_create=True)
	pp.pprint(request.__dict__['http_session'].__dict__)
	request.__dict__['channel_session'].__dict__['_session_cache']['LoggedIn']=True
	request.__dict__['channel_session'].save()
	pp.pprint(request.__dict__['channel_session'].__dict__)
	pp.pprint(dir(request))
	pp.pprint(dir(request.__dict__['channel_session']))
	pp.pprint(dir(request.__dict__['http_session']))
	print request.__dict__['channel_session'].get('LoggedIn')
	print request.__dict__['http_session'].get('LoggedIn')
# routes defined for channel calls
# this is similar to the Django urls, but specifically for Channels

channel_routing = [
       #route('http.request',processRequest),
       route('websocket.connect',connectChannelid),
       route('websocket.receive',connectedChannel)
]