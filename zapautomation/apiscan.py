__author__ = 'Sagar Popat - @popat_sagar' 

import requests
import sys
import argparse
import urllib
import json
import time
import signal


apikey = '<YOUR_ZAPAPI_KEY>'

def start_scan(target_url,data,method):

    alerts = 'http://localhost:8080/JSON/core/view/alerts/?zapapiformat=JSON&baseurl=&start=&count=&apikey='+apikey
    status = 'http://localhost:8080/JSON/ascan/view/status/?zapapiformat=JSON&scanId={0}&apikey='+apikey
    #api_data = "'"+data+"'"
    api_data = data
    url = 'http://localhost:8080/JSON/core/action/sendRequest/?zap%20apiformat=JSON&apikey=fgvopa8tm7q54bbgiq0dpdnjtc&request='+method+'%20%20'+target_url+'%20HTTP%2F1.1%0d%%200aapi-version:1%0d%0aContent-Type:application/json%0d%0a%0d%0a'+urllib.quote(api_data)+'&followRedirects='
    r = requests.get(url)
    if 'id' in r.text:
        print '[+] Send request Sent'
        checkscantree = 'http://localhost:8080/JSON/core/view/urls/?zapapiformat=JSON&apikey='+apikey
        scantree_urls = requests.get(checkscantree)
        scantree_urls = json.loads(scantree_urls.text)
        for url in scantree_urls['urls']:
            if url == target_url:
              ascan_api = 'http://localhost:8080/JSON/ascan/action/scan/?zapapiformat=JSON&url='+target_url+'&recurse=False&inScopeOnly=False&scanPolicyName=&method=&postData=%27'+data+'%27&apikey='+apikey
              try:
                  start_scan = requests.get(ascan_api)
                  scan_id = json.loads(start_scan.text)
                  scan_id = scan_id['scan']
                  while True:
                        status_url = status.format(str(scan_id))
                        scan_status = requests.get(status_url)
                        scan_status = json.loads(scan_status.text)['status']
                        if int(scan_status) >= 0:
                            print "[+]Active Scanned Successfully completed"
                            scan_alert = requests.get(alerts)
                            for vuln in json.loads(scan_alert.text)['alerts']:
                                name = vuln['name']
                                url = vuln['url']
                                print "[+]{0} is vulnerable to {1}".format(url,name)
                            break

                        time.sleep(100)

              except Exception, e:              
                  print "[-]Failed to start active scan"
            else:
                print "[-]URL doesn't exist on scanning tree"
    else:
        print r.text

def get_arg(args=None):
    parser = argparse.ArgumentParser(description='Automating Web Service Penetration testing')
    parser.add_argument('-u', '--url',
                        help='URL of target API',
                        required='True')
    parser.add_argument('-d', '--data',
                        help='JSON data of API')
    parser.add_argument('-m', '--method',
                        help='HTTP request method',
                        default='POST',choices=('GET', 'POST'))
   
    results = parser.parse_args(args)
    return (results.url,
            results.data,
            results.method)

def sigint_handler(signum, frame):
    stop_scan = requests.get("http://localhost:8080/JSON/ascan/action/stopAllScans/?zapapiformat=JSON&formMethod=&apikey="+apikey)
    #print stop_scan.text
    if json.loads(stop_scan.text)['Result'] == "OK":
        print "[+]Scan Successfully stopped"
        sys.exit(1)
    
 
signal.signal(signal.SIGINT, sigint_handler)

if __name__ == '__main__':
    url, data,method = get_arg(sys.argv[1:])
    start_scan(url,data,method)
    
        
