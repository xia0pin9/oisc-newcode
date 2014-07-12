# Written by Sathya Chandran, PhD student, CIS, K-State
# Mar 7 2014
# This script tails the syslog for hosts running Windows identified by Procera
# Inserts the tuple (timestamp, client_ip, 

from pymongo import MongoClient
from pymongo.errors import DuplicateKeyError
import re
from dateutil import parser
import subprocess

def test(str, pattern):
    groups = pattern.match(str)
    if groups:
        print groups.group()

str = "Apr 15 10:19:00 plr01 pld: [Ruleset:Notice] FW: [Log Windows XP Hosts] (6) 129.130.121.163:2077->54.209.211.62:80 (HTTP)"

pattern = re.compile(r'(\w+\s*\d+\s*\d+:\d+:\d+)\s*plr01 pld: \[Ruleset:Notice\] FW: \[Log\s*([\w\.\s-]+)\s* Hosts\] \(6\)\s*(\d+.\d+.\d+.\d+):\d+->\d+.\d+.\d+.\d+:\d+\s*.*')

command = 'tail -F /data/winxp/winxp.log'

p = subprocess.Popen(command, stdout = subprocess.PIPE, shell = True)

conn = MongoClient()

for line in iter(p.stdout.readline,''):

    if pattern.match(line):
        groups = pattern.match(line)
        timestamp =  groups.group(1)
        platform = groups.group(2)
        client_ip = groups.group(3)
        timestamp = parser.parse(timestamp)
        ts_day = timestamp.strftime("%Y_%m_%d")
        ts_hour = timestamp.strftime("%Y_%m_%d_%H")
         
        record = {}
        record["timestamp"] = timestamp
        record["_id"] = client_ip
        record["platform"] = platform

        coll_name = 'coll_'+ts_hour
        
        db_name = 'xp_hosts_procera_'+ts_day

        db = conn[db_name]

        coll = db[coll_name]
	try:
            coll.insert(record)
	except DuplicateKeyError:
	    pass
conn.close()
