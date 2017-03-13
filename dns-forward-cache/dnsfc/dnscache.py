# !/usr/bin/python3
# -*- coding: utf-8 -*-
import socket
import struct
import time

from dnsfc.utils import get_logger
from dnsfc.rr_parse import DNSPacket

CACHE = {}  # TODO: Make constant cache
LOGGER = get_logger()


def ask(data, addr):
    """Ask 'addr' about 'data'"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(0.1)
    with sock:
        try:
            sock.sendto(data, addr)
            response = sock.recv(4096)
            return DNSPacket(response)
        except socket.error:
            return ask(data, ('8.8.8.8', 53))


class Server:
    """Server class"""
    def __init__(self, f_addr, sock):
        self.forwarder = f_addr
        self.sock = sock

    def forward(self, data, key):
        pack = ask(data, self.forwarder)
        # now key - question name, value - records, not whole packet
        CACHE[key] = pack.records
        return bytes(pack)

    def request(self, data, client):
        pack = DNSPacket(data)
        key = pack.query_name
        if key in CACHE:
            packet = self.pack_packet(key, data)
            self.sock.sendto(packet, client)
        else:
            LOGGER.info(
                'Ask %s:%s',
                self.forwarder[0],
                self.forwarder[1],
            )
            self.sock.sendto(self.forward(data, key), client)

    def pack_packet(self, key, data):
        cdata = CACHE[key]
        for recs in cdata:
            for r in recs:
                if not time.time() - r.time <= r.ttl:
                    LOGGER.info(
                        'Ask %s:%s (%s [too old])',
                        self.forwarder[0],
                        self.forwarder[1],
                        r.name,
                    )
                    return self.forward(data, key)
        LOGGER.info('From cache')
        ind = 12 + data[12:].find(b'\x00') + 5
        question = data[12:ind]
        counts = struct.pack('!HHHH', 1, len(cdata[0]), len(cdata[1]), len(cdata[2]))
        recs = b''.join([bytes(r) for rrs in cdata for r in rrs])
        packet = data[:2] + b'\x81\x80' + counts + question + recs
        return packet
