#!/usr/bin/evn python

from pymongo import MongoClient 
from dateutil import parser
import subprocess
import re

command = 'tail -F /data/ids-ua/ids-ua.log'

p = subprocess.Popen(command, stdout = subprocess.PIPE, shell = True)

client = MongoClient()

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


for line in iter(p.stdout.readline,''):
    ts, firewall_ip, firewall_port, remote_ip, remote_port, user_agent = line.rstrip().split(",")
    ts = parser.parse(ts.split("Strings:")[1].replace("/","-"))
    platform = get_platform(user_agent) 
    if platform is not None:
        record = {}
    	record['timestamp'] = ts
    	record['firewall_ip'] = firewall_ip
    	if firewall_port != '':
            record['firewall_port'] = int(firewall_port)
    	else:
	    record['firewall_port'] = ''
    	record['remote_ip'] = remote_ip
    	if remote_port != '':
            record['remote_port'] = int(remote_port)
    	else:
	    record['remote_port'] = ''
    	record['user_agent'] = user_agent
	record['os'] = platform
    	dbName = 'ids_ua_log_' + ts.strftime("%Y_%m_%d") 
    	db = client[dbName]
    	collName = 'idsua_' + ts.strftime("%Y_%m_%d_%H")
    	coll = db[collName]
    	coll.insert(record)
	#print record
client.close()
