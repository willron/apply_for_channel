#!/usr/bin/env python
# -*- coding:utf-8 -*-

import ConfigParser
import commands
import redis
import sys
import os


path = sys.argv[0]
config_path = path if os.path.isdir(path) else os.path.dirname(path)
c = ConfigParser.ConfigParser()
c.read(os.path.join(config_path, 'config.cfg'))
REDIS_SERVER = c.get('Redis', 'host')
REDIS_PORT = c.getint('Redis', 'port')
REDIS_DB = c.getint('Redis', 'db')


print '#'*20+'Clear Redis'+'#'*20
r = redis.StrictRedis(host=REDIS_SERVER, port=REDIS_PORT, db=REDIS_DB)
def clearkeys(key):
    print 'Cleaning:', key
    r.delete(key)
if len(r.keys()) != 0:
    map(lambda x: clearkeys(x), r.keys('TransferChannelInfo_*'))
else:
    print 'Redis is empty!'
print ''


print '#'*20+'Clear iptables'+'#'*20
iptables_file = '/opt/iptables.sh'
with open(iptables_file, 'r') as f:
    lines = f.readlines()
    for i, line in enumerate(lines):
        if line.startswith('#BEGIN<<<===>>>DO_NOT_DELETE_THIS_LINE'):
            clear_file = lines[0:i+1]
            print 'Number of deleted line:', len(lines) - len(clear_file)
            break
newfile = open(iptables_file, 'w')
newfile.writelines(clear_file)
newfile.close()
# print '#'*20+'Loading iptables'+'#'*20
commands.getstatusoutput('/bin/bash ' + iptables_file)
print ''

print '#'*20+'Clear at'+'#'*20
status, output = commands.getstatusoutput("/usr/bin/atq | awk '{print $1}'")
if status == 0:
    if output != '':
        for i in output.split('\n'):
            s, o = commands.getstatusoutput('/usr/bin/atrm %s' % i)
            if s == 0:
                print 'Delete job:', i
    else:
        print 'Job empty!'
else:
    print 'Can\'t run atq'
print ''
print 'Clean Done!'
