"""AdySys URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.11/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.conf.urls import url, include
    2. Add a URL to urlpatterns:  url(r'^blog/', include('blog.urls'))
"""
from django.conf.urls import url
from django.contrib import admin
from django.conf.urls import include
from Clients import views as BaseAdySys
from AdySys import views as Generic
import os


urlpatterns = [
    url(r'^$',BaseAdySys.index),
    url(r'^id/index.html',BaseAdySys.index),
    url(r'^admin/', admin.site.urls),
    url(r'^login.sys$',Generic.index,name="login"),
    #url("", include('django_socketio.urls'))
]
try :
	os.mkdir("/tmp/DjangoTemp")
except Exception,e:
	print("{}".format(e))