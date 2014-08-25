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
from IPy import IP
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

def follow(thefile):
    thefile.seek(0,2) # Go to the end of the file
    while True:
        line = thefile.readline()
        if not line:
            continue
        yield line


def get_platform(user_agent):
    osversion = ''
    if "CFNetwork" in user_agent:
        us_temp = user_agent[user_agent.find("CFNetwork"):].split()[0]
        if us_temp in mac_os_ua:
            osversion = mac_os_ua[us_temp]
        else:
            us_temp = user_agent[user_agent.find("Darwin"):].split()[0]
            if us_temp in mac_os_ua:
                osversion = mac_os_ua[us_temp]
    elif "Macintosh" in user_agent:
        if "OS" in user_agent:
            us_temp = user_agent[user_agent.find("OS"):].split(";")[0]
            osversion = "Mac " + us_temp.split(")")[0].replace("_", ".")
        else:
            osversion = "Macintosh unknown"
    elif "Mac" in user_agent:
        osprefix = ''
        if "iPhone" in user_agent or "iPad" in user_agent or \
                "iPod" in user_agent:
            osprefix = "i"
        else:
            osprefix = "Mac "
        if "OS" in user_agent:
            us_temp = user_agent[user_agent.find("OS"):].replace("_", ".")
            osversion = osprefix + us_temp
            osversion = osversion.replace("like", "(")
            osversion = osversion.replace(")", "(").split("(")[0]
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
            us_temp = user_agent[user_agent.find("Windows"):]
            osversion = us_temp.split(";")[1].strip()
            if "Windows" in osversion:
                us_temp = user_agent[user_agent.find("Windows"):]
                osversion = "Windows " + us_temp.split()[1]
            elif osversion.count('.') == 2:
                index_temp = osversion.split('.')[0] + "." + \
                    osversion.split('.')[1]
                if "Windows NT " + index_temp in win_os_ua: 
                    osversion = win_os_ua["Windows NT " + index_temp]
                else:
                    osversion = "Windows unknown"
            else:
                osversion = "Windows " + osversion
        elif result2:
            index_temp = result2.group(0).split(".")[0] + "." + \
                result2.group(0).split(".")[1]
            if index_temp in win_os_ua:
                osversion = win_os_ua[index_temp]
            else:
                osversion = "Windows unknown"
        elif result3:
            us_temp = user_agent[user_agent.find("Windows"):].split(";")[0]
            osversion = us_temp.split(")")[0].strip()
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
    elif "ubuntu" in user_agent or "Linux" in user_agent or \
            "linux" in user_agent:
        osversion = "Linux"

    if osversion == "" or osversion == None:
        osversion = "Other" 
    return osversion


#command = 'tail -F /data/tslog/ts.log'

pattern = re.compile(r'[.:\w\s]+ TrueSight: (\d+/\d+/\d+\s+\d+:\d+:\d+\.\d+)'
                     '.*CIP: (.*) URL: (.*) UserAgent: (.*) Referrer: (.*)'
                     ' SIP: (.*) SP: (.*) Username: (.*)')

#p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)

client = MongoClient()

for line in follow(open("/data/tslog/ts.log")):
    matched = pattern.match(line)
    if matched:
	try:
            date = matched.group(1)
            date = parser.parse(date)
            client_ip = matched.group(2)
            remote_ip = matched.group(6)
            remote_port = matched.group(7)
            user_agent = matched.group(4)
            platform = get_platform(user_agent)
        except:
            print "Log line info:", line
            raise
        if client_ip != "":
            if IP(client_ip).iptype() == "PRIVATE" or \
                    client_ip.startswith("129.130."):
                tsDay = date.strftime("%Y_%m_%d")
                tsHour = date.strftime("%Y_%m_%d_%H")
                record = {}
                record["timestamp"] = date
                record["client_ip"] = client_ip
                record["remote_ip"] = remote_ip
                record["remote_port"] = remote_port
                record["os"] = platform
                record["user_agent"] = user_agent
                db_name = 'ts_ua_log_' + tsDay
                coll_name = 'tsua_' + tsHour
                db = client[db_name]
                coll = db[coll_name]
                coll.insert(record)
client.close()
