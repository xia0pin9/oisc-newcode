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


def get_time_range(ts, t):
    lts = ts - datetime.timedelta(minutes=t)
    rts = ts + datetime.timedelta(minutes=t)
    return {"$gte": lts, "$lt": rts}


# Only FW IPs within 129.130.18.* range are NATed, need to get Internal IP
def get_ips_from_fw():
    iplist = {}
    results = natcoll.find({"firewall_ip": {"$regex": "^129.130.18."}})
    for record in results:
        key = record['firewall_ip'] + "_" + record['firewall_port'] + "_" + \
            record['remote_ip'] + "_" + record['remote_port']
        if key not in iplist:
            iplist[key] = [(record['internal_ip'], record['start_time'])]
        else:
            iplist[key].append((record['internal_ip'], record['start_time']))
    return iplist


def get_intip_from_fw(request):
    internal_ip = ""
    deltats = datetime.timedelta(minutes=1)
    key = request['firewall_ip'] + "_" + str(request['firewall_port']) + "_" + \
        request['remote_ip'] + "_" + str(request['remote_port'])
    global iplist
    if key in iplist:
        if len(iplist[key]) == 1:
            internal_ip = iplist[key][0][0]
        else:
            reqts = request['start_time']
            for (intip, fwts) in iplist[key]:
                if fwts == reqts:
                    internal_ip = intip
                    break
                if reqts - deltats < fwts and fwts < reqts + deltats:
                    internal_ip = intip
        # internal_ip = record["internal_ip"]
    return internal_ip


def get_mac_from_dhcp(request):
    mac_address = ""
    results = dhcpcoll.find(request)
    if results.count() > 1:
        print "Error: multiple mac address returned for the request", request
    for record in results:
        mac_address = record['mac_address']
    return mac_address


def get_mac_from_arp(request):
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
natdb = fwclient["incident_response_nat_built_"+lastHour.strftime("%Y_%m_%d")]
natcoll = natdb["nat_start_" + lastHour.strftime("%Y_%m_%d_%H")]
iplist = get_ips_from_fw()

client = MongoClient()
osrepudb = client["incident_response_os_reputation"]
osrepucoll = osrepudb["os_reputation"]

ipmacdb = client["incident_response_ipmac"]
ipmaccoll = ipmacdb["ipmac_" + lastHour.strftime("%Y_%m_%d")]
dhcpdb = client["incident_response_dhcp_log_" + lastHour.strftime("%Y_%m_%d")]
dhcpcoll = dhcpdb["dhcplog_" + lastHour.strftime("%Y_%m_%d_%H")]

idsdb = client["ids_ua_log_" + lastHour.strftime("%Y_%m_%d")]
idscoll = idsdb["idsua_" + lastHour.strftime("%Y_%m_%d_%H")]

for document in idscoll.find():
    source = ''
    mac = ''
    firewall_ip = document['firewall_ip']
    ts_range = get_time_range(document['timestamp'], 5)
    request = {}
    if firewall_ip.startswith("129.130.18."):
        request['remote_ip'] = document['remote_ip']
        request['firewall_ip'] = firewall_ip
        request['firewall_port'] = document['firewall_port']
        request['remote_port'] = document['remote_port']
        request['start_time'] = document['timestamp']
        # print "NAT records", firewall_ip
        internal_ip = get_intip_from_fw(request)
        if internal_ip != "":
            requestb = {}
            requestb['ip_address'] = internal_ip
            requestb['timestamp'] = ts_range
            mac = fill_zero(get_mac_from_arp(requestb))
            if mac != "":
                source = "IDSn - ARP"
            else:
                mac = fill_zero(get_mac_from_dhcp(requestb))
                if mac != "":
                    source = "IDSn - DHCP"
        if mac != "" and mac != "00":
            record = {}
            record['mac_address'] = mac
            record['user_agent'] = document['user_agent']
            results = osrepucoll.find(record)
            if results.count() == 0:
                record['os'] = document['os']
                record['source'] = source
                record['first_time'] = document['timestamp']
                record['last_time'] = document['timestamp']
                record['count'] = 1
                osrepucoll.insert(record)
            else:
                osrepucoll.update(record, {'$inc': {'count': 1},
                                  '$set': {'last_time': document['timestamp']
                                  }}, upsert=True, multi=False)
    else:
        request['ip_address'] = firewall_ip
        request['timestamp'] = ts_range
        mac = fill_zero(get_mac_from_arp(request))
        if mac != "":
            source = "IDS - ARP"
        else:
            mac = fill_zero(get_mac_from_dhcp(request))
            if mac != "":
                source = "IDS - DHCP"
        if mac != "" and mac != "00":
            record = {}
            record['mac_address'] = mac
            record['user_agent'] = document['user_agent']
            results = osrepucoll.find(record)
            if results.count() == 0:
                record['os'] = document['os']
                record['source'] = source
                record['first_time'] = document['timestamp']
                record['last_time'] = document['timestamp']
                record['count'] = 1
                osrepucoll.insert(record)
            else:
                osrepucoll.update(record, {'$inc': {'count': 1},
                                  '$set': {'last_time': document['timestamp']
                                  }}, upsert=True, multi=False)

tsdb = client["ts_ua_log_" + lastHour.strftime("%Y_%m_%d")]
tscoll = tsdb["tsua_" + lastHour.strftime("%Y_%m_%d_%H")]

for document in tscoll.find():
    source = ''
    mac = ''
    client_ip = document['client_ip']
    ts = document['timestamp']
    ts_range = get_time_range(ts, 5)
    request = {}
    request['ip_address'] = client_ip
    request['timestamp'] = ts_range
    mac = fill_zero(get_mac_from_arp(request))
    if mac != "":
        source = "TrueSight - ARP"
    else:
        mac = fill_zero(get_mac_from_dhcp(request))
        if mac != "":
            source = "TrueSight - DHCP"
    if mac != "" and mac != "00":
        record = {}
        record['mac_address'] = mac
        record['user_agent'] = document['user_agent']
        results = osrepucoll.find(record)
        if results.count() == 0:
            record['os'] = document['os']
            record['source'] = source
            record['first_time'] = document['timestamp']
            record['last_time'] = document['timestamp']
            record['count'] = 1
            osrepucoll.insert(record)
        else:
            osrepucoll.update(record, {'$inc': {'count': 1},
                              '$set': {'last_time': document['timestamp']
                              }}, upsert=True, multi=False)

client.close()
fwclient.close()
