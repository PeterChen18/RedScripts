#!/usr/local/bin/python
import securitycenter
import csv
import os
import sys
import json
import getopt
import time

TIMESTAMP=(time.strftime("%Y%m%d.%H%M%S"))

def get_cred(credfile):
    if not os.path.exists(credfile):
        print '!!! CRED file does not exist!  Aborting. !!!'
        dumb_cred_id = "admin-user"
        dumb_cred_password = "MyVirtualPassword-DonotUseIt"
        sys.exit(1)
    with open(credfile) as creds:
            authdata = json.load(creds)
    #print data
    return authdata

def get_opts():
    credfile = ''
    scan = ''
    createscan = 0
    options = list()
    try:
        opts, args = getopt.getopt(sys.argv[1:],"hc:s:",["help", "cred=", "scan="])
    except getopt.GetoptError:
        print 'ERROR %s %s' % (opts, args)
        sys.exit(2)
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print '%s -c|--cred <JSON Creds> [-s|--scan <Scan Name String>] [ -h|--help ]' % ( os.path.basename(__file__))
            sys.exit(0)
        elif opt in ("-c", "--cred"):
            credfile = arg
        elif opt in ("-s", "--scan"):
            scan = arg
        #print 'CMD2 %s %s' % (opt, arg)
    options = {
        'credfile': credfile,
        'scan': scan,
    }
    return options

def list_scans(sc):
    data = {}
    for scan_list in sc.get('scan').json()['response']['usable']:
        resp = sc.get('scan/%s' % scan_list['id'], params={'fields': 'name,ipList,description'})
        ipcount = 0
        for item in resp.json()['response']['ipList']:
            # This is where we work to convert the pipe and newline delimited
            # format of the data that SecurityCenter uses to a list of tuples
            for line in item['ipList'].split('\n'):
                ipcount = ipcount + 1

        data[resp.json()['response']['id']] = {
            'name': resp.json()['response']['name'],
            'description': resp.json()['response']['description'],
            'ipcount': ipcount,
        }
    return data

def list_scan_results(sc):
    print '"ScanResult ID","ScanResult Name"'
    for scan_list in sc.get('scanResult').json()['response']['usable']:
        #print 'SCANLIST: "%s"' % json.dumps(scan_list)
        scanresid = scan_list['id']
        scanresname = scan_list['name']
        print '"%s","%s"' % ( scanresid, scanresname )


def get_scan_detail(sc,scanid):
    data = {}
#   asset_list = sc.get('asset/$s' % aid)
    resp = sc.get('scanResult/%s' % scanid, params={'dataFormat': 'IPv4'}).json()['response']
    #print 'RESP "%s"' % resp
    jresp = json.dumps(resp)
    print jresp

def get_scan_results_ips(sc,scanid):
    print '"addresses","name","description","tags"'
#   asset_list = sc.get('asset/$s' % aid)
    #ip_addresses = sc.get('scanResult/%s' % scanid).json()['response.progress.scanners.scannedIPs']
    scanners = sc.get('scanResult/%s' % scanid, params={'resultType': 'IPv4', 'fields': 'name,progress,scanners'}).json()['response']['progress']['scanners']
    old_name = scanners[0]['name']
    newscanresname = "DYNAMIC_SCAN_%s_%s" % (old_name,TIMESTAMP)   
    new_desc = "Dynamic Scan for %s created on %s" % (old_name,TIMESTAMP) 
    new_tag = "Dynamic"    
    for scandevs in  scanners:
        ip_addresses = json.dumps(scandevs['scannedIPs'])
        print '%s,"%s","%s","%s"' % (ip_addresses,newscanresname,new_desc,new_tag)

    #print 'RESP "%s"' % resp
    #jresp = json.dumps(ip_addresses)


if __name__ == '__main__':

    credfile = ''
    scan = ''

    cmd_opts = get_opts()
    credfile = cmd_opts['credfile']
    scan = cmd_opts['scan']

    authdata = get_cred(credfile)
    schost = authdata["sc"]
    user = authdata['user']
    password = authdata['password']

    sc = securitycenter.SecurityCenter5(schost)
    sc.login(user, password)

    if scan != '':
        get_scan_detail(sc,scan)
        #get_scan_results_ips(sc,scan)
        sys.exit(0)
    else:
        list_scan_results(sc)
        sys.exit(0)

    # scan_lists = list_scan_results(sc)
    # print '"SC Scan ID","SC Scan Name","SC Scan Description","IPCount"'
    # for scid in scan_lists:
    #     sclist = scan_lists[scid]['name']
    #     scdesc = scan_lists[scid]['description']
    #     ipcount = scan_lists[scid]['ipcount']
    #     print '"%s","%s","%s","%s"' % (scid, sclist, scdesc, ipcount)
    #             #else:
    #                 #print 'SKIP "%s"' % scid
    # sys.exit(0)


