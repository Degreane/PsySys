from channels.auth import channel_session_user,channel_session_user_from_http,http_session
from channels.routing import route, route_class
from channels.sessions import channel_and_http_session,channel_session
from Crypto.Hash import MD5
import json
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


@channel_session_user
def connectedChannel(message):
	print("Message Connected decrypting in Clients")
	print message.__dict__
	#print apps.get_models()
	#pp.pprint(message["text"])
	# the message["text"] is base64 encoded so it should be decoded accordingly. before being sent to decryptor.
	# the encKey is personal for each connected host thus no two hosts derive the same encKey thus security is attained.
	encKey=MD5.new(str(message.reply_channel)).hexdigest()
	decryptedJSON=decrypt(b64decode(message['text']),encKey)
	# next parse content of decryptedJSON into a formal JSON
	messageJSON=json.loads(decryptedJSON)
	if messageJSON["target"] == 'login':
		Client = user.objects(lgnName=messageJSON['lgnName'],lgnPass=messageJSON['lgnPass'] )
		if Client.count() == 1:
			#print "Client Accepted"
			#set redirect page
			redirectPage="/index.html?lgnName={}&lgnPass={}".format(messageJSON['lgnName'],messageJSON['lgnPass'])
			encryptedRedirectPage=b64encode(encrypt(redirectPage,encKey))
			#print dir(message.http_session)
			#message.http_session={"LoggedIn":True}
			#print message.http_session.keys()
			message.reply_channel.send({
			        'text':json.dumps({'verdict':encryptedRedirectPage})
			})
			
		else:
			#print "Client Not Accepted"
			redirectPage="False"
			encryptedRedirectPage=b64encode(encrypt(redirectPage,encKey))
			message.reply_channel.send({
			        'text':json.dumps({'verdict':encryptedRedirectPage})
			})			


@channel_session_user_from_http
def connectChannelid(message):
	#print("Getting ID {}".format(str(message.reply_channel)))
	print "in Clients Routing "
	print message.__dict__
	message.reply_channel.send({'accept':True,
                                'text':json.dumps({'enc':MD5.new(str(message.reply_channel)).hexdigest()})
                                })
# routes defined for channel calls
# this is similar to the Django urls, but specifically for Channels

channel_routing = [
       route('websocket.connect',connectChannelid),
       route('websocket.receive',connectedChannel)
]