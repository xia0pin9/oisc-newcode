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

def getIntIPFromFW(request):
    internal_ip = ""
    results = natcoll.find(request)
    for record in results:
        if internal_ip != "" and record["internal_ip"] != internal_ip:
            print "Multiple internal IP returned for the request"
        internal_ip = record["internal_ip"]

def getMacFromDhcp(request):
    mac_address = ""
    results = dhcpcoll.find(request)
    for record in results:
        if mac_address != "" and record['mac_address'] != mac_address:
	    print "Error: multiple mac address returned for the request"
        mac_address = record['mac_address']
    return mac_address

def getMacFromArp(request):
    mac_address = ""
    results = ipmaccoll.find(request)
    if results.count() > 1:
        print "Multiple ARP entries returned,", request
    for record in results:
        mac_address = record['mac_address']
    return mac_address

now = datetime.datetime.now()
lastHour = now - datetime.timedelta(hours=1)

fwclient = MongoClient("129.130.0.44", 27017)
natdb = fwclient["incident_response_nat_built_" + lastHour.strftime("%Y_%m_%d")]
natcoll = natdb["nat_start_" + lastHour.strftime("%Y_%m_%d_%H")]

client = MongoClient()
ipmacdb = client["incident_response_ipmac"]
ipmaccoll = ipmacdb["ipmac_" + lastHour.strftime("%Y_%m_%d")]
dhcpdb = client["incident_response_dhcp_log_" + lastHour.strftime("%Y_%m_%d")]
dhcpcoll = dhcpdb["dhcplog_" + lastHour.strftime("%Y_%m_%d_%H")]

idsdb = client["ids_ua_log_" + lastHour.strftime("%Y_%m_%d")]
idscoll = idsdb["idsua_" + lastHour.strftime("%Y_%m_%d_%H")]

for document in idscoll.find():
    firewall_ip = document['firewall_ip']
    ts_range = getTimeRange(document['timestamp'])
    request = {}
    if firewall_ip.startswith("129.130.18."):
        request['remote_ip'] = document['remote_ip']
        request['firewall_ip'] = firewall_ip
        request['firewall_port'] = document['firewall_port']
        request['remote_port'] = document['remote_port']
        request['start_time'] = ts_range
        internal_ip = getIntIPFromFW(request)
        if internal_ip != "":
            requestb = {}
            requestb['ip_address'] = internal_ip
            requestb['timestamp'] = ts_range
     	    if getMacFromArp(requestb) != "":
        	print "IDSn - ARP", firewall_ip, getMacFromArp(requestb) #results.count()
            elif getMacFromArp(requestb) != "":
        	print "IDSn - DHCP", firewall_ip, getMacFromDhcp(requestb)
            else:
                pass
        	#print "IDSn source, mac address not found.", firewall_ip
        else:
	    pass
	    #print "IDSn source, internal ip not found"
    else:
        request['ip_address'] = firewall_ip
        request['timestamp'] = ts_range
        if getMacFromArp(request) != "":
            print "IDS - ARP", firewall_ip, getMacFromArp(request) #results.count()
        elif getMacFromArp(request) != "":
            print "IDS - DHCP", firewall_ip, getMacFromDhcp(request)
        else:
            pass
            #print "IDS source, mac address not found.", firewall_ip


tsdb = client["ts_ua_log_" + lastHour.strftime("%Y_%m_%d")]
tscoll = tsdb["tsua_" + lastHour.strftime("%Y_%m_%d_%H")]

for document in tscoll.find():
    client_ip = document['client_ip']
    ts = document['timestamp']
    ts_range = getTimeRange(ts)
    request = {}
    request['ip_address'] = client_ip
    request['timestamp'] = ts_range
    #mac = getMacFromArp(request)
    if getMacFromArp(request) != "":
        print "TrueSight - ARP", client_ip, getMacFromArp(request) #results.count()
    elif getMacFromArp(request) != "":
        print "TrueSight - DHCP", client_ip, getMacFromDhcp(request)
    else:
        pass
	#print "TrueSight source, mac address not found.", client_ip
    #break
