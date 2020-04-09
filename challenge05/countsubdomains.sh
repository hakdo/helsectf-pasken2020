#!/bin/bash

cat ../artefacts/eve-dns.json | jq '.dns.rrname' |grep journalsystem |sort -u |wc -w |md5