# Written by Sathya Chandran, PhD student, CIS, K-State
# Apr 29 2013
# This script tails the TrueSight log file on black-mamba for TrueSight logs
# The username and client_ip address are extracted and stored in a MongoDB database

from pymongo import Connection
import datetime
import os
import re
import shlex
from dateutil import parser
import datetime
import subprocess
import time

command = 'tail -F /data/tslog/ts.log'

conn = Connection()

dbName = 'incident_response_eid_ip'

collName = 'eid_ip'

db = conn[dbName]

coll = db[collName]

coll.ensure_index([('time', 1), ('client_ip', 1)])

coll.ensure_index([('eid', 1)])

pattern = re.compile(r'[.:\w\s]+ TrueSight: (\d+/\d+/\d+\s+\d+:\d+:\d+).*CIP: (.*) URL: (.*) UserAgent: (.*) Referrer: (.*) SIP: (.*) SP: (.*) Username: (.*)')

p = subprocess.Popen(command, stdout = subprocess.PIPE, shell = True)
                  
for line in iter(p.stdout.readline,''):
    matched = pattern.match(line)
    if matched:
        username = matched.group(8)
        if username:
            time = matched.group(1)
            time = parser.parse(time)
            client_ip = matched.group(2)
            record = {}
            record['time'] = time
            record['client_ip'] = client_ip
            record['eid'] = username
            coll.insert(record)
conn.close()
