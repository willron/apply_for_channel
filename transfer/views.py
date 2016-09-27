# -*- coding: utf-8 -*-
import os
import sys
import ldap
import time
import shlex
import redis
import socket
import subprocess
import commands
import ConfigParser
from get_my_ip.get_my_ip import get_my_ip
from django.shortcuts import render
from django.shortcuts import HttpResponseRedirect
from django.shortcuts import HttpResponse


# LDAP_SERVER = '192.168.0.4'
# AD_POSTFIX = 'hksz.cn'
# TRANSFER_SERVER = '112.74.164.195'
# PORT_RANGE_MIN = 10000
# PORT_RANGE_MAX = 20000
# IFNAME = 'eth0'
# REDIS_SERVER = '192.168.0.223'
# REDIS_PORT = 6379
# REDIS_DB = 2


path = sys.argv[0]
config_path = path if os.path.isdir(path) else os.path.dirname(path)
c = ConfigParser.ConfigParser()
c.read(os.path.join(config_path, 'config.cfg'))

VARS = dict([(i, dict(c.items(i)))for i in c.sections()])
if 'Redis' not in VARS or 'Transfer' not in VARS or 'LdapHost' not in VARS:
    assert False, 'Check Config File!'

REDIS_SERVER = VARS['Redis'].get('host', 'localhost')
REDIS_PORT = int(VARS['Redis'].get('port', '6379'))
REDIS_DB = int(VARS['Redis'].get('db', '2'))

LDAP_SERVER = VARS['LdapHost'].get('host')
AD_POSTFIX = VARS['LdapHost'].get('postfix')

TRANSFER_SERVER = VARS['Transfer'].get('host')
TRANSFER_SERVER_PORT = int(VARS['Transfer'].get('sshport'))

PORT_RANGE_MIN = int(VARS['Localhost'].get('port_range_min'))
PORT_RANGE_MAX = int(VARS['Localhost'].get('port_range_max'))
IFNAME = VARS['Localhost'].get('eth', 'ech0')
MY_HOST_IP = VARS['Localhost'].get('ip', get_my_ip(IFNAME))
USE_FIREWALL = VARS['Localhost'].get('use_firewall', 'True')

ALL_LIMIT = int(VARS['Limit'].get('all_limit', '500'))
EACHONE_LIMIT = int(VARS['Limit'].get('eachone_limit', '20'))
PORTDENY = [int(i) for i in VARS['PortDeny'].get('portdeny', '22').split(',')]

if 'VIP' in VARS:
    PORT_VIP = VARS['VIP']

def redis_get_useinfo(loginname=''):

    key_str = 'TransferChannelInfo_'+loginname+'_*' if loginname != '' else 'TransferChannelInfo_*'
    r = redis.StrictRedis(host=REDIS_SERVER, port=REDIS_PORT, db=REDIS_DB)
    apply_lists = r.keys(key_str)
    apply_info = []
    if apply_lists:
        for i in apply_lists:
            info = r.hgetall(i)
            info['ttl'] = r.ttl(i)
            apply_info.append(info)
    return sorted(apply_info, key=lambda x: x['ttl'], reverse=True)


def ldap_auth(address, username, password):
    conn = ldap.initialize('ldap://' + address)
    conn.protocol_version = 3
    conn.set_option(ldap.OPT_REFERRALS, 0)

    try:
        username = username + '@' + AD_POSTFIX
        result = conn.simple_bind_s(username, password)
    except ldap.INVALID_CREDENTIALS:
        return "账号或密码错误！"
    except ldap.SERVER_DOWN:
        return "服务器错误！"
    except ldap.LDAPError, e:
        if type(e.message) == dict and e.message. has_key('desc'):
            return "其它错误： " + e.message['desc']
        else:
            return "其它错误： " + e
    finally:
        conn.unbind_s()
    return True


def runcmd(ip, port, times, client_ip):

    for i in range(PORT_RANGE_MIN, PORT_RANGE_MAX + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        try:
            s.bind(('0.0.0.0', i))
        except Exception:
            continue
        finally:
            s.close()
        ssh_channel_cmd = '/usr/bin/ssh -C -N -L*:%s:%s:%s root@%s -p 9055 -o ServerAliveInterval=60' % (i, ip, port, TRANSFER_SERVER)

        results = subprocess.Popen(shlex.split(ssh_channel_cmd))

        pid = results.pid

        kill_cmd = "echo 'kill -9 %s'|at now +%sminutes" % (pid, times*60)
        commands.getstatusoutput(kill_cmd)

        if USE_FIREWALL == 'True':
            cmd = 'iptables -A INPUT -s %s -p tcp -m state --state NEW -m tcp --dport %s -j ACCEPT' % (client_ip, i)
            firewall_cmd = "sed -i -e 's/iptables -P INPUT .*/iptables -P INPUT DROP/' -e '$a %s' /opt/iptables.sh" % cmd
            firewall_timeout = "echo \"sed -i '/%s/d' /opt/iptables.sh&&/bin/bash /opt/iptables.sh\"|at now +%sminutes" % (cmd, times*60)
            commands.getstatusoutput(firewall_cmd)
            commands.getstatusoutput(firewall_timeout)
        else:
            firewall_cmd = "sed -i -e 's/iptables -P INPUT .*/iptables -P INPUT ACCEPT/'"
            commands.getstatusoutput(firewall_cmd)

        commands.getstatusoutput('/bin/bash /opt/iptables.sh')

        return i, pid


def index(request):
    if 'LoginName' not in request.session:
    # 用户未登录跳转
        return HttpResponseRedirect('/login')
    if request.POST:
        try:
            CLIENT_ADDR = request.META['REMOTE_ADDR']
            LoginName = request.session['LoginName']
            ServerIP, ServerPort, Times = request.POST['ServerIP'], int(request.POST['ServerPort']), int(request.POST['Time'])
            createtime = time.strftime('%H:%M:%S', time.localtime(time.time()))

            r = redis.StrictRedis(host=REDIS_SERVER, port=REDIS_PORT, db=REDIS_DB)
            # eachone_num = len(r.keys('TransferChannelInfo_'+LoginName+'_*'))
            # all_num = len(r.keys('TransferChannelInfo_*'))
            # if eachone_num >= EACHONE_LIMIT or all_num >= ALL_LIMIT:
            #     assert False, '连接数过多，请稍候再提交'
            # if ServerPort in PORTDENY:
            #     assert False, '禁止转发到远程服务器的%s端口' % ServerPort
            auth = auth_center(LoginName, ServerIP, ServerPort)
            if auth is True:
                transfer_port, transfer_pid = runcmd(ServerIP, ServerPort, Times, CLIENT_ADDR)
                # transfer_port, transfer_pid = 31223, 33435
            else:
                assert False, auth

            KEY = 'TransferChannelInfo_'+LoginName+'_'+str(transfer_pid)
            r.hset(KEY, 'TransferPort', transfer_port)
            r.hset(KEY, 'TransferIP', MY_HOST_IP)
            r.hset(KEY, 'DestServerIP', ServerIP)
            r.hset(KEY, 'DestServerPort', ServerPort)
            r.hset(KEY, 'TransferTimes', Times)
            r.hset(KEY, 'CreateTime', createtime)
            r.expire(KEY, Times*3600)
            return render(request, 'index.html', {'Msg': '提交成功', 'apply_info': redis_get_useinfo(LoginName)})
        except AssertionError, e:
            return render(request, 'index.html', {'Msg': e, 'apply_info': redis_get_useinfo(LoginName)})
    else:
        request.session.set_expiry(1800)
        LoginName = request.session['LoginName']
        return render(request, 'index.html', {'apply_info': redis_get_useinfo(LoginName),
                                              'EACHONE_LIMIT': EACHONE_LIMIT, 'ALL_LIMIT': ALL_LIMIT})


def login(request):
    if request.POST:
        LoginName = request.POST['LoginName']       # 获取登录名
        LoginPassword = request.POST['LoginPassword']       # 获取密码

        auth = ldap_auth(LDAP_SERVER, LoginName, LoginPassword)

        if auth == True:
            # 将用户登录名以及用户的ftp路径写入session
            request.session['LoginName'] = LoginName
            return HttpResponseRedirect('/')
        else:
            return render(request, 'login.html', {'LoginErrMsg': auth})
    else:
        return render(request, 'login.html')


def logout(request):
    from django.contrib.auth import logout
    logout(request)
    return HttpResponseRedirect('/login')


def auth_center(loginname, serverip, serverport):
    LoginName = loginname
    ServerIP = serverip
    ServerPort = serverport

    flush_vip = ConfigParser.ConfigParser()
    flush_vip.read(os.path.join(config_path, 'config.cfg'))
    sections = c.sections()
    if 'VIP' in sections:
        new_vip = dict(flush_vip.items('VIP'))
    if 'PortDeny' in sections:
        new_portdeny = [int(i) for i in flush_vip.get('PortDeny', 'portdeny').split(',')]

    global PORTDENY
    global PORT_VIP
    PORT_VIP = new_vip
    PORTDENY = new_portdeny

    r = redis.StrictRedis(host=REDIS_SERVER, port=REDIS_PORT, db=REDIS_DB)
    connections = r.keys('TransferChannelInfo_'+LoginName+'_*')
    eachone_num = len(connections)
    all_num = len(r.keys('TransferChannelInfo_*'))
    for x in [i for i in connections]:
        exist_dest = r.hget(x, 'DestServerIP') + ':' + r.hget(x, 'DestServerPort')
        if ServerIP + ':' + str(ServerPort) == exist_dest:
            return '已存在相同的服务器端口的转发'
    if eachone_num >= EACHONE_LIMIT or all_num >= ALL_LIMIT:
        return '连接数过多，请稍候再提交'
    if ServerPort in PORTDENY:
        if str(ServerPort) in PORT_VIP:
            if LoginName in PORT_VIP[str(ServerPort)].split(','):
                return True
        return '禁止转发到远程服务器的%s端口' % ServerPort
    return True
