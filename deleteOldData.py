#!/usr/bin/python

# Written by Sathya Chandran, PhD student, CIS, K-State
# May 10 2013
# This script is executed via crontab every day at midnight to delete the oldest collection (currently 3 days) in the NAT and ARP databases

from pymongo import MongoClient 
import datetime
import os
import re
import shlex
from dateutil import parser
import datetime
import subprocess


today = datetime.datetime.today()
timeDelta = datetime.timedelta(days=7)
nDaysBefore = today - timeDelta
nDaysBefore = parser.parse(str(nDaysBefore))
#year = str(nDaysBefore.year)
#month = str(nDaysBefore.month).zfill(2)
#day = str(nDaysBefore.day).zfill(2)

#ts = year+'_'+month+'_'+day

client = MongoClient()

dbs = client.database_names()

for name in dbs:
    dbName = 'incident_response_nat_built_'
    if name.startswith(dbName):
	ts = name.split("_built_")[1].replace("_", "-")
	if parser.parse(ts) < nDaysBefore:
	    client.drop_database(name)

    dbName = 'incident_response_nat_teardown_'
    if name.startswith(dbName):
	ts = name.split('_teardown_')[1].replace("_", "-")
	if parser.parse(ts) < nDaysBefore:
	    client.drop_database(name)

    dbName = 'xp_hosts_requests_db_'
    if name.startswith(dbName):
	ts = name.split('_requests_db_')[1].replace("_", "-")
	if parser.parse(ts) < nDaysBefore:
	    client.drop_database(name)

    dbName = 'xp_hosts_procera_'
    if name.startswith(dbName):
	ts = name.split('_hosts_procera_')[1].replace("_", "-")
	if parser.parse(ts) < nDaysBefore:
	    client.drop_database(name)

    dbName = 'incident_response_ipmac'
    if name == dbName:
	for collName in client[dbName].collection_names():
	    if collName.startswith("ipmac"):
		ts = collName.split("ipmac_")[1].replace("_", "-")
		if parser.parse(ts) < nDaysBefore:
		    client[dbName].drop_collection(collName)

    dbName = 'ids_ua_log_'
    if name.startswith(dbName):
	ts = name.split('ids_ua_log_')[1].replace("_", "-")
	if parser.parse(ts) < nDaysBefore:
	    client.drop_database(name)

    dbName = 'ts_ua_log_'
    if name.startswith(dbName):
        ts = name.split('ts_ua_log_')[1].replace("_", "-")
	if parser.parse(ts) < nDaysBefore:
	    client.drop_database(name)

    dbName = "incident_response_dhcp_log_"
    if name.startswith(dbName):
	ts = name.split('_dhcp_log_')[1].replace("_", "-")
	if parser.parse(ts) < nDaysBefore:
	    client.drop_database(name)
#print dbs
client.close()
