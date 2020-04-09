#!/usr/bin/env python3

"""
Find port that is open from netflow logs. Detect by bytes to client different
from 54 (all other flows have this value).

Usage: python3 openport.py ../artefacts/eve-flow.json
"""

import sys, json, hashlib

myfile = sys.argv[1]

if __name__ == "__main__":
    destports = []
    filedata  = open(myfile,'r')
    mydata = filedata.readlines()
    filedata.close()
    openport = None
    for line in mydata:
        datadict = json.loads(line)
        if datadict["flow"]["bytes_toclient"] != 54:
            openport = datadict["dest_port"]
            break
    md5port = hashlib.md5(str(openport).encode('utf-8')).hexdigest()
    print('Open port: ' + str(openport))
    print('MD5 of port number: ' + md5port)