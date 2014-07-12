#!/usr/bin/env python

'''
This script is to be executed every hour, go through the ids_ua_log and ts_ua_log database for hosts that have known os info
'''

from pymongo import MongoClient
import datetime
from dateutil import parser

def getTimeRange(ts):
    lts = ts - datetime.timedelta(minutes=5)
    rts = ts + datetime.timedelta(minutes=5)
    return {"$gte": lts, "$lt": rts}

now = datetime.datetime.now()
lastHour = now - datetime.timedelta(hours=1)

client = MongoClient()
fwclient = MongoClient("129.130.0.44", 27017)
idsdb = client["ids_ua_log_" + lastHour.strftime("%Y_%m_%d")]
idscoll = idsdb["idsua_" + lastHour.strftime("%Y_%m_%d_%H")]

for document in idscoll.find():
    firewall_ip = document['firewall_ip']
    remote_ip = document['remote_ip']
    ts_range = getTimeRange(document['timestamp'])
    request = {}
    request['firewall_ip'] = firewall_ip
    request['remote_ip'] = remote_ip
    request['timestamp'] = ts_range

tsdb = client["ts_ua_log_" + lastHour.strftime("%Y_%m_%d")]
tscoll = tsdb["tsua_" + lastHour.strftime("%Y_%m_%d_%H")]

for document in tscoll.find():
    client_ip = document['client_ip']
    ts_range = getTimeRange(document['timestamp'])
    request = {}
    request['client_ip'] = client_ip
    request['timestamp'] = ts_range
    print request
