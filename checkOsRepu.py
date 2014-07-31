#!/usr/bin/env python

import sys
import getopt
import datetime
from pymongo import MongoClient
from prettytable import PrettyTable


def usage():
    print """
    Usage:
    ------
        python %s -s -m <mac_address>

    Valid options are:

        -h      You are looking at this.
        -s      Show summary of the os reputation records.
        -u      Show user agent information.
        -m      Specify mac address (e.g. 00:21:55:be:8a:80).
        -o      Specify OS type (e.g. "Windows XP").
        -c      Specify confidence level for mac or os.
    """ % (sys.argv[0])


def get_mac_info(mac_address, show_ua, confidence, osrepucoll):
    request = {}
    request["mac_address"] = mac_address
    results = osrepucoll.find(request)
    if results.count() == 0:
        print "No records found for mac address:", mac_address
    else:
        print "OS reputation for host:", mac_address
        if not show_ua:
            oslists = {}
            for result in results:
                os = result['os']
                if os not in oslists:
                    oslists[os] = [result['count'], result['first_time'],
                                   result['last_time'], result['source']]
                else:
                    if result['first_time'] < oslists[os][1]:
                        oslists[os][1] = result['first_time']
                    if result['last_time'] > oslists[os][2]:
                        oslists[os][2] = result['last_time']
                    oslists[os][0] = oslists[os][0] + result['count']
            total = sum([oslists[x][0] for x in oslists])
            x = PrettyTable(["os", "percent", "count", "first_saw",
                            "last_saw", "source"])
            while len(oslists) > 0:
                count = 0
                osname = ''
                for record in oslists:
                    if oslists[record][0] > count:
                        count = oslists[record][0]
                        osname = record
                record = oslists[osname]
                percent = "%.2f" % (float(count*1.0/total)*100)
                x.add_row([osname, percent, count, record[1],
                          record[2], record[3]])
                oslists.pop(osname)
            print x
        else:
            y = PrettyTable(["os", "count", "user_agent"])
            for record in results:
                y.add_row([record['os'], record['count'], record['user_agent']])
            print y


def get_os_info(os, show_ua, confidence, osrepucoll):
    results = osrepucoll.find({"os": {'$regex': os}})
    if results.count() == 0:
        print "No records found for os type:", os
    else:
        print "Host list for os type:", os
        if not show_ua:
            maclists = {}
            for result in results:
                mac = result['mac_address']
                if mac not in maclists:
                    maclists[mac] = [result['count'], result['first_time'],
                                     result['last_time'], result['source']]
                else:
                    if result['first_time'] < maclists[mac][1]:
                        maclists[mac][1] = result['first_time']
                    if result['last_time'] > maclists[mac][2]:
                        maclists[mac][2] = result['last_time']
                    maclists[mac][0] += result['count']
            x = PrettyTable(['mac', 'percent', 'count', 'first_time',
                             'last_time', 'source'])
            for mac in maclists:
                total = 0
                all_results = osrepucoll.find({"mac_address": mac})
                for record in all_results:
                    total += record['count']
                percent = maclists[mac][0]*100.0/total
                if percent >= confidence:
                    percent = "%.2f" % percent
                    x.add_row([mac, percent, maclists[mac][0], maclists[mac][1],
                              maclists[mac][2], maclists[mac][3]])
            print x
        else:
            y = PrettyTable(["mac_address", "count", "user_agent"])
            for record in results:
                y.add_row([record['mac_address'], record['count'],
                          record['user_agent']])
            print y

def main():
    if len(sys.argv) < 2:
        usage()
        sys.exit(0)
    else:
        try:
            options = ["help", "show", "ua", "mac=", "os=", "confidence="]
            opts, args = getopt.getopt(sys.argv[1:], "hsum:o:c:", options)
        except getopt.GetoptError, err:
            print str(err)
            usage()
            sys.exit(1)

    mac_address = ''
    show_ua = False
    summary = False
    os = ''
    confidence = 0

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-s", "--summary"):
            summary = True
        elif o in ("-m", "--mac"):
            mac_address = a
        elif o in ("-u", "--user_agent"):
            show_ua = True
        elif o in ("-o", "--os"):
            os = a
        elif o in ("-c", "--confidence"):
            confidence = int(a)

    client = MongoClient()
    osrepudb = client["incident_response_os_reputation"]
    osrepucoll = osrepudb["os_reputation"]
    if summary:
        macs = list(osrepucoll.distinct('mac_address'))
        print "Reputation system contains %s distinct mac record" % len(macs)
        print "Mac addresses that contains more than 10000 recoords:"
        for mac in macs:
            try:
                results = osrepucoll.find({"mac_address": mac})
                for record in results:
                    if record['count'] > 10000:
                        print mac, record['count'], record['os']
                        # x.add_row([mac, record['count'], record['os']])
            except (KeyboardInterrupt, SystemExit):
                sys.exit(0)
            except:
                print "DB lookup error."

    if mac_address == "" and os == "":
        if confidence > 0:
            print "Confidence must be specified with mac address or os"
        if show_ua:
            print "Show user agent must be specified with mac address or os"
        sys.exit()
    if mac_address != "":
        get_mac_info(mac_address, show_ua, confidence, osrepucoll)
    if os != "":
        get_os_info(os, show_ua, confidence, osrepucoll)
    client.close()

if __name__ == "__main__":
    main()
