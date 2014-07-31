#!/usr/bin/evn python

from pymongo import MongoClient
from dateutil import parser
import subprocess
import re

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
                osversion = win_os_ua["Windows NT " + index_temp]
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

    if osversion == "":
        osversion = "Other" 
    return osversion

command = 'tail -F /data/ids-ua/ids-ua.log'

p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)

client = MongoClient()

for line in iter(p.stdout.readline, ''):
    ts, fwip, fwport, remote_ip, remote_port, us = line.rstrip().split(",")
    ts = parser.parse(ts.split("Strings:")[1].replace("/", "-"))
    platform = get_platform(us)
    if platform is not None:
        record = {}
        record['timestamp'] = ts
        record['firewall_ip'] = fwip
        if fwport != '':
            record['firewall_port'] = int(fwport)
        else:
            record['firewall_port'] = ''
        record['remote_ip'] = remote_ip
        if remote_port != '':
            record['remote_port'] = int(remote_port)
        else:
            record['remote_port'] = ''
        record['user_agent'] = us
        record['os'] = platform
        dbName = 'ids_ua_log_' + ts.strftime("%Y_%m_%d")
        db = client[dbName]
        collName = 'idsua_' + ts.strftime("%Y_%m_%d_%H")
        coll = db[collName]
        coll.insert(record)

client.close()
