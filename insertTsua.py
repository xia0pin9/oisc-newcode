#!/usr/bin/env python

'''
This script tails the TrueSight log file and looks for user agent information 
Inserts the record composed of client IP, user agent, and timestamp.
'''
from pymongo import MongoClient 
import ipaddress
import os
import re
import shlex
from dateutil import parser
import datetime
import subprocess
import time

mac_os_ua = {}
win_os_ua = {}
with open("mac_os_agents.txt") as f:
    for line in f:
        cfn, os = line.strip().split(",")
        mac_os_ua[cfn] = os.strip()
with open("win_os_agents.txt") as f:
    for line in f:
        nt, os = line.strip().split(",")
        win_os_ua[nt] = os.strip()

def get_platform(user_agent):
    osversion = ''
    if "CFNetwork" in user_agent:
        if user_agent[user_agent.find("CFNetwork"):].split()[0] in mac_os_ua:
            osversion = mac_os_ua[user_agent[user_agent.find("CFNetwork"):].split()[0]]
        elif user_agent[user_agent.find("Darwin"):].split()[0] in mac_os_ua:
            osversion = mac_os_ua[user_agent[user_agent.find("Darwin"):].split()[0]]
    elif "Macintosh" in user_agent:
        if "OS" in user_agent:
            osversion = "Mac " + user_agent[user_agent.find("OS"):].split(";")[0].split(")")[0].replace("_", ".")
        else:
            osversion = "Macintosh unknown"
    elif "Mac" in user_agent:
        osprefix = ''
        if "iPhone" in user_agent or "iPad" in user_agent or "iPod" in user_agent :
            osprefix = "i"
        else:
            osprefix = "Mac "
        if "OS" in user_agent:
            osversion = osprefix + user_agent[user_agent.find("OS"):].replace("_",".")
            osversion = osversion.replace("like","(").replace(")","(").split("(")[0]
        else:
            osversion = "Mac unknown"
    elif "iPhone" in user_agent:
        result1 = re.search("OS \d(\.\d)+", user_agent)
        result2 = re.search("\d(\.\d)+", user_agent)
        if result1:
            osversion = "iOS " + result1.group(0)
        elif "Apple" in user_agent and result2:
            osversion = "iOS " + result2.group(0)

    if "Windows" in user_agent:
        result1 = re.search("Windows;", user_agent)
        result2 = re.search("Windows NT \d(\.\d)+", user_agent)
        result3 = re.search("Windows \d(\.\d)?", user_agent)
        if result1:
            osversion = user_agent[user_agent.find("Windows"):].split(";")[1].strip()
            if "Windows" in osversion:
                osversion = "Windows " + user_agent[user_agent.find("Windows"):] .split()[1]
            elif osversion.count('.') == 2:
                osversion = win_os_ua["Windows NT "+osversion.split('.')[0]+"."+osversion.split('.')[1]]
            else:
                osversion = "Windows " + osversion
        elif result2:
            if result2.group(0).split(".")[0]+"."+result2.group(0).split(".")[1] in win_os_ua:
                osversion = win_os_ua[result2.group(0).split(".")[0]+"."+result2.group(0).split(".")[1]]
            else:
                osversion = "Windows unknown"
        elif result3:
            osversion = user_agent[user_agent.find("Windows"):].split(";")[0].split(")")[0].strip()
            if "Windows NT " + osversion.split()[1] in win_os_ua:
                osversion = win_os_ua["Windows NT "+osversion.split()[1]]
            else:
                osversion = "Windows " + osversion.split()[1]
        else:
            osversion = "Windows unknown"
    elif "Android" in user_agent or "android" in user_agent:
        result = re.search("Android \d(\.\d)+", user_agent)
        if result:
            osversion = result.group(0)
        else:
            osversion = "Android unknown"
    elif "ubuntu" in user_agent or "Linux" in user_agent or "linux" in user_agent:
        osversion = "Linux"

    if osversion == "":
        osversion = None
        #print user_agent
        #continue
    return osversion

command = 'tail -F /data/tslog/ts.log'

pattern = re.compile(r'[.:\w\s]+ TrueSight: (\d+/\d+/\d+\s+\d+:\d+:\d+).*CIP: (.*) URL: (.*) UserAgent: (.*) Referrer: (.*) SIP: (.*) SP: (.*) Username: (.*)')

p = subprocess.Popen(command, stdout = subprocess.PIPE, shell = True)

client = MongoClient()

for line in iter(p.stdout.readline,''):
    matched = pattern.match(line)
    if matched:
        date = matched.group(1)
        date = parser.parse(date)
        client_ip = matched.group(2)
	remote_ip = matched.group(6)
	remote_port = matched.group(7)
        user_agent = matched.group(4)
        platform = get_platform(user_agent)
	#if not platform and user_agent.startswith("gsa-kstate") and client_ip != "129.130.254.182":
        #    print client_ip, user_agent
        if platform is not None:
            tsDay = date.strftime("%Y_%m_%d")
            tsHour = date.strftime("%Y_%m_%d_%H")
            record = {}
            record["timestamp"] = date
            record["client_ip"] = client_ip
	    record["remote_ip"] = remote_ip
	    record["remote_port"] = remote_port
            record["os"] = platform
	    record["user_agent"] = user_agent
            db_name = 'ts_ua_log_'+tsDay
            coll_name = 'tsua_'+tsHour
            db = client[db_name]
	    #print record
            coll = db[coll_name]
            coll.insert(record)
client.close()
