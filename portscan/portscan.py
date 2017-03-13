# !/usr/bin/python
# -*- coding: utf-8 -*-
import socket
from collections import OrderedDict
import struct
import re
from random import randint
from multiprocessing import Pool


ID = randint(1, 65535)
DNSPACK = struct.pack("!HHHHHH", ID, 256, 1, 0, 0, 0) + b"\x06google\x03com\x00\x00\x01\x00\x01"
TCP_PACKS = OrderedDict([
    ("dns" , struct.pack("!H", len(DNSPACK)) + DNSPACK),
    ("smtp" , b'HELO World'),
    ("http" , b'GET / HTTP/1.1\r\nHost: google.com\r\n\r\n'),
    ("pop3" , b"AUTH")
])
UDP_PACKS = OrderedDict([
    ("dns" , DNSPACK),
    ("ntp" , struct.pack('!BBBb11I', (2 << 3) | 3, *([0]*14)))
])


def check_sign(pack):
    """Check packet signature"""
    if pack[:4].startswith(b"HTTP"):
        return 'http'
    elif re.match(b"[0-9]{3}", pack[:3]):
        return "smtp"
    if struct.pack("!H", ID) in pack:
        return "dns"
    elif pack.startswith(b"+"):
        return "pop3"
    else:
        try:
            struct.unpack('!BBBb11I', pack)
        except:
            return "..."
        else:
            return "ntp"


def is_port_in_use(addr):
    """Is port in use (tcp)"""
    ip, port = addr
    socket.setdefaulttimeout(1)
    for prot in TCP_PACKS:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.connect(addr)
                sock.sendall(TCP_PACKS[prot])
                data = sock.recv(12)
                return port, check_sign(data)
            except:
                continue

def is_port_in_use_udp(addr):
    """Is port in use (udp)
    TODO: Check open udp port with ICMP"""
    ip, port = addr
    res = "..."
    socket.setdefaulttimeout(1)
    for prot in UDP_PACKS:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.sendto(UDP_PACKS[prot], addr)
                data, _ = sock.recvfrom(48)
                res = check_sign(data)
            except:
                continue
    if res != "...":
        return port, res


class PortScannerAsync:
    """Async scan of ports class"""
    def __init__(self, ip, udp=False):
        self.addr = ip
        self.pool = Pool()
        self.udp = udp

    def start(self, start=1, end=65535):
        rng = [(self.addr, i) for i in range(start, end)]
        if self.udp:
            func = is_port_in_use_udp
        else:
            func = is_port_in_use
        return self.pool.imap(func, rng)
