# Written by Sathya Chandran, PhD student, CIS, K-State
# Aug 15 2013
# This script tails dhcp logs in /media/data/dhcplog/dhcp.log extracts timestamp, IP address, MAC address, and Host Name and stores in a Mongo DB database
# Current retention period: 3 days

from pymongo import Connection
import os
import datetime
import os
import re
from dateutil import parser
import datetime
import subprocess

pattern = re.compile(r'(\w+\s*\d+\s*\d+:\d+:\d+).*?DHCPACK on.*?(\d+.\d+.\d+.\d+)\s+to\s+([\w\d]+:[\w\d]+:[\w\d]+:[\w\d]+:[\w\d]+:[\w\d]+)\s+\(?([:.\w\d-]*)\)?\s*via.*')

command = 'tail -F /data/dhcplog/dhcp.log'

p = subprocess.Popen(command, stdout = subprocess.PIPE, shell = True)

conn = Connection()

for line in iter(p.stdout.readline,''):
    matched = pattern.match(line)
    if(matched):
        timestamp = matched.group(1)
        ipAddress = matched.group(2)
        macAddress = matched.group(3)
        hostName = matched.group(4)
        
        date = parser.parse(timestamp)
        year = str(date.year)
        month = str(date.month).zfill(2)
        day = str(date.day).zfill(2)
        hour = str(date.hour).zfill(2)
        minute = str(date.minute).zfill(2)
        second = str(date.second).zfill(2)
        tsDay = year+'_'+month+'_'+day
        tsHour = tsDay+'_'+hour
        ts = year+'-'+month+'-'+day+' '+hour+':'+minute+':'+second
        ts = parser.parse(ts)

        record = {}
        record['timestamp'] = ts
        record['ip_address'] = ipAddress
        record['mac_address'] = macAddress
        record['host_name'] = hostName
        
        dbName = 'incident_response_dhcp_log_'+tsDay

        db = conn[dbName]

        collName = 'dhcplog_'+tsHour

        coll = db[collName]
        
        coll.insert(record)
    else:
        continue

conn.close()
