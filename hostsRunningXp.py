# Written by Sathya Chandran, PhD student, CIS, K-State
# Mar 3, 2014
# This script tails the TrueSight log file and looks for requests from hosts running Windows XP
# Inserts the record composed of client IP, user agent, and timestamp.

from pymongo import MongoClient 
import ipaddress
import os
import re
import shlex
from dateutil import parser
import datetime
import subprocess
import time


def get_platform(user_agent):

    if "Windows NT 5.1" in user_agent or "Windows NT 5.2" in user_agent or "Windows XP" in user_agent:
        return "Windows XP"
    elif "Intel Mac OS X 10.3" in user_agent or "Intel Mac OS X 10_3" in user_agent :
        return "Mac OS X 10.3"
    elif "Intel Mac OS X 10.4" in user_agent or "Intel Mac OS X 10_4" in user_agent :
        return "Mac OS X 10.4"
    elif "Intel Mac OS X 10.5" in user_agent or "Intel Mac OS X 10_5" in user_agent :
        return "Mac OS X 10.5"
    else:
        return None


def is_home_network(client_ip):

    client_ip = ipaddress.ip_address(client_ip)
    for home_net in home_nets:
        if client_ip in home_net:
            return True
        
net1 = ipaddress.ip_network("129.130.0.0/16")
net2 = ipaddress.ip_network("10.130.0.0/16")
net3 = ipaddress.ip_network("10.131.0.0/16")

home_nets = [net1, net2, net3]

command = 'tail -F /data/tslog/ts.log'

pattern = re.compile(r'[.:\w\s]+ TrueSight: (\d+/\d+/\d+\s+\d+:\d+:\d+).*CIP: (.*) URL: (.*) UserAgent: (.*) Referrer: (.*) SIP: (.*) SP: (.*) Username: (.*)')

p = subprocess.Popen(command, stdout = subprocess.PIPE, shell = True)

client = MongoClient()

for line in iter(p.stdout.readline,''):
    matched = pattern.match(line)
    if matched:
        try:
            date = matched.group(1)
            date = parser.parse(date)
            client_ip = matched.group(2)
            user_agent = matched.group(4)
            platform = get_platform(user_agent)
        except:
            print "Log error lifo:", line
            continue
        if (platform is not None) and (is_home_network(client_ip)):
            tsDay = date.strftime("%Y_%m_%d")
            tsHour = date.strftime("%Y_%m_%d_%H")
            record = {}
            record["timestamp"] = date
            record["client_ip"] = client_ip
            record["platform"] = platform
            db_name = 'xp_hosts_requests_db_'+tsDay
            coll_name = 'coll_'+tsHour
            db = client[db_name]
            coll = db[coll_name]
            coll.insert(record)

client.close()
