#!/usr/bin/env python3

import sys, hashlib, json

filename = sys.argv[1]
myfile = open(filename, 'r')
mydata = myfile.readlines()
myfile.close()

reply_guy_string = ''
domains = []

for line in mydata:
    sample = json.loads(line)
    try:
        if sample["dns"]["type"]=="answer":
            if sample["dns"]["rcode"] == 'NOERROR':
                if sample["dns"]["rrtype"] == 'A':
                    reply_guy_string = reply_guy_string + sample["dns"]["rrname"]
                    domains.append(sample["dns"]["rrname"])
    except:
        pass

md5out = hashlib.md5(reply_guy_string.encode('utf-8')).hexdigest()
print('Existing domains identified: ')
for domain in domains:
    print(domain)
print('MD5: ' + md5out)