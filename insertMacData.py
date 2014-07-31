# Written by Sathya Chandran, PhD student, CIS, K-State
# Apr 4 2013
# This script is executed via crontab every 15mins to dump IP address to
# MAC address mapping to mongoDB database

from pymongo import Connection
import shlex
from dateutil import parser
import datetime
import subprocess

"""
Global vars:

"""
def deleteCollection():
    today = datetime.datetime.today()
    timeDelta = datetime.timedelta(days=3)
    threeDaysBefore = today - timeDelta
    threeDaysBefore = parser.parse(str(threeDaysBefore))
    year = str(threeDaysBefore.year)
    month = str(threeDaysBefore.month).zfill(2)
    day = str(threeDaysBefore.day).zfill(2)
    ipMacDb = 'incident_response_ipmac'
    ipMacColl = 'ipmac_'+year+'_'+month+'_'+day
    conn = Connection()
    db = conn[ipMacDb]
    db.ipMacColl.drop()
    conn.close()

def getRemoteFileName() :
    timeDelta = datetime.timedelta(minutes = 15)
    macdirectory = '/macdump/'
    timestamp = parser.parse(str(datetime.datetime.now() - timeDelta))
    year = str(timestamp.year)
    month = str(timestamp.month).zfill(2)
    day = str(timestamp.day).zfill(2)
    hour = str(timestamp.hour).zfill(2)
    minute = str(timestamp.minute).zfill(2)
    date = year+'-'+month+'-'+day
    remotefileName = macdirectory+date+'/macdump.'+year+month+day+'.'+hour+minute
    global gTimestamp
    gTimestamp = date+' '+hour+':'+minute+':'+'00'
    return remotefileName

def getTodaysDate():
    today = parser.parse(str(datetime.datetime.today()))
    year = str(today.year)
    month = str(today.month).zfill(2)
    day = str(today.day).zfill(2)
    return year+'_'+month+'_'+day

def fill_zero(mac_address):
    if len(mac_address) != 17:
        mac_address = ":".join([x.zfill(2) for x in mac_address.split(":")])
    return mac_address

# Execution starts from here

gTimestamp = ''

conn = Connection()

dbName = 'incident_response_ipmac'

collName = 'ipmac_'+getTodaysDate()

db = conn[dbName]

coll = db[collName]

coll.ensure_index([('timestamp', -1), ('ip_address', -1)])

coll.ensure_index([('mac_address', -1)])

remoteFileName = getRemoteFileName()

localFileName = '/home/sathya/macdumpTemp.log'

command = 'scp nucleus:'+remoteFileName+' '+localFileName

p = subprocess.call(command, shell = True)

inFile = open('/home/sathya/macdumpTemp.log')

while 1:
    lines = inFile.readlines(100000)
    if not lines:
        break;
    else:
        for line in lines:
            ip_mac_dic = shlex.split(line)
            ip_address = ip_mac_dic[0]
            mac_address = ip_mac_dic[1]
            #id = gTimestamp+'$$$'+ip_address
            record = {}
            #record['_id'] = id
            record['timestamp'] = parser.parse(gTimestamp)
            record['ip_address'] = ip_address
            record['mac_address'] = fill_zero(mac_address)
            coll.insert(record)
inFile.close()
conn.close()
