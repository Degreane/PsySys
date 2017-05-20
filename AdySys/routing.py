from channels.routing import route, route_class
from channels.staticfiles import StaticFilesConsumer
from channels.sessions import channel_session
from channels.auth import channel_session_user,channel_session_user_from_http
from channels import Group, Channel
import json 
import pprint as pp

@channel_session_user
def connectedChannel(message):
    print("Message Connected ")
    pp.pprint(json.loads(message["text"]))
    print str(message.reply_channel)

@channel_session_user_from_http
def connectChannel(message):
    print('Connecting Channel')
    myPasskey=str(message.reply_channel)
    message.reply_channel.send({'accept':True})
@channel_session_user_from_http
def connectChannelid(message):
    print("Getting ID {}".format(str(message.reply_channel)))
    message.reply_channel.send({'accept':True,
                                'text':json.dumps({'enc':str(message.reply_channel)})
                                })
# routes defined for channel calls
# this is similar to the Django urls, but specifically for Channels


channel_routing = [
    route('websocket.receive',connectedChannel),
    route('websocket.connect',connectChannelid,path=r'/id/$'),
    route('websocket.connect',connectChannel)
    
]