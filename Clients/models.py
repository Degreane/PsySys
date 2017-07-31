# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models
import mongoengine as mg
#from mongoengine.visitor import Q

mg.connect('SailsAdySys')

class user(mg.Document):
    firstName = mg.StringField()
    lastName = mg.StringField()
    Comment=mg.StringField()
    isClient=mg.BooleanField()
    isDealer=mg.BooleanField()
    isAdmin=mg.BooleanField()
    InternalId=mg.IntField()
    Credits=mg.IntField()
    Deleted=mg.BooleanField()
    Enabled=mg.BooleanField()
    Country=mg.StringField()
    updatedAt=mg.DateTimeField()
    lgnPass=mg.StringField()
    onPage=mg.BooleanField()
    lgnName=mg.StringField()
    createdAt=mg.DateTimeField()
    Desc=mg.StringField()
    onLine=mg.BooleanField()
    Building=mg.StringField()
    City=mg.StringField()
    Plans=mg.ListField()
    Floor=mg.StringField()
    OTC=mg.BooleanField()
    Phone=mg.StringField()
    Street=mg.StringField()
    Owner=mg.StringField()
    Email=mg.StringField()
    OIP=mg.BooleanField()
    Ip=mg.StringField()
    MAC=mg.StringField()
    Expires=mg.DateTimeField()
    Down=mg.IntField()
    Up=mg.IntField()
    
   

# Create your models here.
class plan(mg.Document):
    Name=mg.StringField()
    Desc=mg.StringField()
    Comment=mg.StringField()
    QuotaUp=mg.IntField()
    QuotaDown=mg.IntField()
    QuotaSchedule=mg.StringField()
    LimitUp=mg.IntField()
    LimitDown=mg.IntField()
    Up=mg.IntField()
    Down=mg.IntField()
    Ip=mg.BooleanField()
    Mac=mg.BooleanField()
    Enabled=mg.BooleanField()
    Deleted=mg.BooleanField()
    InternalId=mg.IntField()
    Radius=mg.BooleanField()
    createdAt=mg.DateTimeField()
    updatedAt=mg.DateTimeField()
    