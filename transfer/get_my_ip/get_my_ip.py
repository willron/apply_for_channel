#!/usr/bin/env python
# -*- coding:utf-8 -*-


import socket
import struct
import fcntl


def get_my_ip(IFNAME):
    getmyip = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(getmyip.fileno(), 0x8915, struct.pack('256s', IFNAME[:15]))[20:24])


