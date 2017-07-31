# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

# Create your models here.
import mongoengine as mg
#from mongoengine.visitor import Q

mg.connect('SailsAdySys')

class plan(mg.Document):