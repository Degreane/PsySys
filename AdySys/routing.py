from channels.routing import route, route_class
from channels.staticfiles import StaticFilesConsumer
import json 
import pprint as pp
def connectedChannel(message):
    print("Message Connected ")
    pp.pprint(json.loads(message["text"]))
# routes defined for channel calls
# this is similar to the Django urls, but specifically for Channels
channel_routing = [
    route('websocket.receive',connectedChannel),
]