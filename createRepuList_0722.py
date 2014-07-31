#!/usr/bin/env python

'''
This script is to be executed every hour, go through the ids_ua_log and
ts_ua_log database for hosts that have known os info.
'''

from pymongo import MongoClient
import datetime
from dateutil import parser


def fill_zero(mac_address):
    if len(mac_address) != 17:
        mac_address = ":".join([x.zfill(2) for x in mac_address.split(":")])
    return mac_address


def getTimeRange(ts):
    lts = ts - datetime.timedelta(minutes=5)
    rts = ts + datetime.timedelta(minutes=5)
    return {"$gte": lts, "$lt": rts}


def getIPsFromFW():
    iplist = {}
    results = natcoll.find({"firewall_ip": {"$regex": "^129.130.18."}})
    for record in results:
        key = record['firewall_ip'] + "_" + record['firewall_port'] + "_" + \
            record['remote_ip'] + "_" + record['remote_port']
        if key not in iplist:
            iplist[key] = [(record['internal_ip'], record['start_time'])]
        else:
            iplist[key].append((record['internal_ip'], record['start_time']))
    # print results.count(), len(iplist)
    return iplist


def getTimeDiff(req, fw):
    diff = 0
    if req < fw:
        diff = (fw - req).seconds
    else:
        diff = (req - fw).seconds
    return diff


def getIntIPFromFW(request):
    internal_ip = ""
    # results = natcoll.find(request)
    key = request['firewall_ip'] + "_" + str(request['firewall_port']) + "_" + \
        request['remote_ip'] + "_" + str(request['remote_port'])
    global iplist
    if key in iplist:
        if len(iplist[key]) == 1:
            internal_ip = iplist[key][0][0]
        else:
            reqts = request['start_time']
            timediff = 600
            for (intip, fwts) in iplist[key]:
                # datetime.datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
                if fwts == reqts:
                    internal_ip = intip
                    break
                if fwts > reqts:
                    continue
                elif timediff < getTimeDiff(reqts, fwts):
                    timediff = getTimeDiff(reqts, fwts)
                    internal_ip = intip
                elif timediff == getTimeDiff(reqts, fwts):
		    if internal_ip == "":
		        internal_ip = intip
                        # print intip, fwts
		    elif internal_ip == intip:
			continue
		    else:
			# print intip, fwts
			print "Potential conflict found:", internal_ip, intip, request
        # internal_ip = record["internal_ip"]
    return internal_ip


def getMacFromDhcp(request):
    mac_address = ""
    results = dhcpcoll.find(request)
    if results.count() > 1:
        print "Error: multiple mac address returned for the request", request
    mac_address = results[0]['mac_address']
    return mac_address


def getMacFromArp(request):
    mac_address = ""
    results = ipmaccoll.find(request)
    if results.count() > 1:
        print "Multiple ARP entries returned,", request
    # for record in results:
    mac_address = results[0]['mac_address']
    return mac_address


now = datetime.datetime.now()
lastHour = now - datetime.timedelta(hours=10)

fwclient = MongoClient("129.130.0.44", 27017)
natdb = fwclient["incident_response_nat_built_"+lastHour.strftime("%Y_%m_%d")]
natcoll = natdb["nat_start_" + lastHour.strftime("%Y_%m_%d_%H")]
iplist = getIPsFromFW()

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
        request['start_time'] = document['timestamp']
        # print "NAT records", firewall_ip
        internal_ip = getIntIPFromFW(request)
        if internal_ip != "":
            requestb = {}
            requestb['ip_address'] = internal_ip
            requestb['timestamp'] = ts_range
            mac = getMacFromArp(requestb)
            if mac != "":
                print "IDSn - ARP", firewall_ip, getMacFromArp(requestb)
            else:
                mac = getMacFromArp(requestb)
                if mac != "":
                    print "IDSn - DHCP", firewall_ip, getMacFromDhcp(requestb)
    else:
        continue
        request['ip_address'] = firewall_ip
        request['timestamp'] = ts_range
        mac = getMacFromArp(request)
        if mac != "":
            print "IDS - ARP", firewall_ip, getMacFromArp(request)
        else:
            mac = getMacFromArp(request)
            if mac != "":
                print "IDS - DHCP", firewall_ip, getMacFromDhcp(request)
            # print "IDS source, mac address not found.", firewall_ip


tsdb = client["ts_ua_log_" + lastHour.strftime("%Y_%m_%d")]
tscoll = tsdb["tsua_" + lastHour.strftime("%Y_%m_%d_%H")]

for document in tscoll.find():
    exit()
    client_ip = document['client_ip']
    ts = document['timestamp']
    ts_range = getTimeRange(ts)
    request = {}
    request['ip_address'] = client_ip
    request['timestamp'] = ts_range
    mac = getMacFromArp(request)
    if mac != "":
        print "TrueSight - ARP", client_ip, getMacFromArp(request)
    else:
        mac = getMacFromArp(request)
        if mac != "":
            print "TrueSight - DHCP", client_ip, getMacFromDhcp(request)
