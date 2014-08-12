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
    python %s -s -c -d -u -m <mac address> -o <os type> -t <threshold>

    Valid options are:

        -h      You are looking at this.
        -s      Show summary of the os reputation records.
        -c      Compress the results into compact view.
        -d      Dump all the mac address only.
        -u      Show user agent information.
        -m      Specify mac address (e.g. 00:21:55:be:8a:80).
        -o      Specify OS type (e.g. "Windows XP").
        -t      Specify threshold level for mac to show.
    """ % (sys.argv[0])


def get_mac_info(mac_address, show_ua, threshold, osrepucoll):
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
                    oslists[os] = [result['count'],
                                   result['first_time'].replace(microsecond=0),
                                   result['last_time'].replace(microsecond=0),
                                   result['source']]
                else:
                    if result['first_time'] < oslists[os][1]:
                        oslists[os][1] = result['first_time'].replace(microsecond=0)
                    if result['last_time'] > oslists[os][2]:
                        oslists[os][2] = result['last_time'].replace(microsecond=0)
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
                percent = count*100.0/total
                if percent >= threshold:
                    percent = "%.2f" % percent
                    x.add_row([osname, percent, count, record[1],
                          record[2], record[3]])
                oslists.pop(osname)
            print x
        else:
            for record in results:
                print record['os'].ljust(20), '\t', record['count'], '\t', record['user_agent']


def get_os_info(os, show_ua, dump, threshold, compact, osrepucoll):
    results = osrepucoll.find({"os": {'$regex': os}})
    if results.count() == 0:
        print "No records found for os type:", os
    else:
        if not dump:
            print "Host list for os type:", os
        if not show_ua:
            maclists = {}
            for result in results:
                mac = result['mac_address']
                if mac not in maclists:
                    maclists[mac] = [result['count'],
                                     result['first_time'].replace(microsecond=0),
                                     result['last_time'].replace(microsecond=0),
                                     result['source']]
                else:
                    if result['first_time'] < maclists[mac][1]:
                        maclists[mac][1] = result['first_time'].replace(microsecond=0)
                    if result['last_time'] > maclists[mac][2]:
                        maclists[mac][2] = result['last_time'].replace(microsecond=0)
                    maclists[mac][0] += result['count']
            if not compact:
                for mac in maclists:
                    total = 0
                    oslists = {}
                    osinfo = "\tOS Info: "
                    all_results = osrepucoll.find({"mac_address": mac})
                    for record in all_results:
                        total += record['count']
                        if record['os'] not in oslists:
                            oslists[record['os']] = record['count']
                        else:
                            oslists[record['os']] += record['count']
                    while len(oslists) > 0:
                        count = 0
                        osname = ''
                        for record in oslists:
                            if oslists[record] > count:
                                count = oslists[record]
                                osname = record
                        if osinfo == "\tOS Info: ":
                            osinfo += osname + "(%s)" % str(count)
                        else:
                            osinfo += ", " + osname + "(%s)" % str(count)
                        oslists.pop(osname)
                    percent = "%.2f".rjust(6) % float(maclists[mac][0]*100.0/total)
                    print mac, percent, osinfo
            else:
                x = PrettyTable(['mac', 'percent', 'count', 'first_time',
                                'last_time', 'source'])
                for mac in maclists:
                    total = 0
                    all_results = osrepucoll.find({"mac_address": mac})
                    for record in all_results:
                        total += record['count']
                    index = maclists[mac]
                    percent = index[0]*100.0/total
                    if percent >= threshold:
                        percent = "%.2f" % percent
                        if not dump:
                            x.add_row([mac, percent, index[0], index[1],
                                      index[2], index[3]])
                        else:
                            print mac
                if not dump:
                    print x
        else:
            for record in results:
                print record['mac_address'], '\t',record['count'], '\t',record['user_agent']
def main():
    if len(sys.argv) < 2:
        usage()
        sys.exit(0)
    else:
        try:
            options = ["help", "summary", "dump", "ua", "compact",
                       "mac=", "os=", "threshold="]
            opts, args = getopt.getopt(sys.argv[1:], "hsudcm:o:t:", options)
        except getopt.GetoptError, err:
            print str(err)
            usage()
            sys.exit(1)

    mac_address = ''
    show_ua = False
    summary = False
    dump = False
    compact = False
    os = ''
    threshold = 0

    for o, a in opts:
        if o in ("-h", "--help"):
            usage()
            sys.exit()
        elif o in ("-s", "--summary"):
            summary = True
        elif o in ("-c", "--compact"):
            compact = True
        elif o in ("-m", "--mac"):
            mac_address = a
        elif o in ("-u", "--user_agent"):
            show_ua = True
        elif o in ("-o", "--os"):
            os = a
        elif o in ("-t", "--threshold"):
            threshold = int(a)
        elif o in ("-d", "--dump"):
            dump = True

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
        if threshold > 0:
            print "Confidence must be specified with mac address or os"
        if show_ua:
            print "Show user agent must be specified with mac address or os"
        sys.exit()
    if mac_address != "":
        get_mac_info(mac_address, show_ua, threshold, osrepucoll)
    if os != "":
        get_os_info(os, show_ua, dump, threshold, compact, osrepucoll)
    client.close()

if __name__ == "__main__":
    main()
