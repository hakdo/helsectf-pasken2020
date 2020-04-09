#!/usr/bin/env python3

"""
Extract unique destionation ports from netflow logs in JSON and output number.
Challenge01 solution: python3 countports.py ../artefacts/eve-flow.json
"""

import sys, json, hashlib

myfile = sys.argv[1]

if __name__ == "__main__":
    destports = []
    filedata  = open(myfile,'r')
    mydata = filedata.readlines()
    filedata.close()
    for line in mydata:
        datadict = json.loads(line)
        dp = datadict["dest_port"]
        if dp not in destports:
            destports.append(dp)
    numports = len(destports)
    md5ports = hashlib.md5(str(numports).encode('utf-8')).hexdigest()
    print('Number of ports: ' + str(len(destports)))
    print('MD5 of number of ports: ' + md5ports)