# !/usr/bin/python3
# -*- coding: utf-8 -*-
import socket
import time
import struct
import argparse
import sys
from multiprocessing import Process


CACHE = {} #Cache
TYPES = {
            1: 'A',
            2: 'NS',
            3: 'MD',
            4: 'MF',
            5: 'CNAME',
            6: 'SOA',
            7: 'MB',
            8: 'MG',
            9: 'MR',
            10: 'NULL',
            11: 'WKS',
            12: 'PTR',
            13: 'HINFO',
            14: 'MINFO',
            15: 'MX',
            16: 'TXT' #code -> type 
}
CLASSES = {
            1: 'IN',
            2: 'CS',
            3: 'CH',
            4: 'HS', #code -> class
}


def get_type(b):
    """Get type by b"""
    return TYPES[struct.unpack('!H', b)[0]]


def get_class(b):
    """Get class by b"""
    return CLASSES[struct.unpack('!H', b)[0]]


def parse_records(name, data, count):
    """Parse 'count' records in data"""
    records = []
    pointer = 0
    for _ in range(count):
        rr = RR(name, data[pointer:])
        records.append(rr)
        pointer += 12 + rr.ln
    return records


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


class DNSPacket:
    """DNSPacket class"""
    def __init__(self, data):
        self._bytes = data
        self.header = list(struct.unpack("!HHHHHH", self._bytes[0:12]))
        self._qname = None
        self._qname = self.qname
        oth = data[12 + len(self.qname) + 5:]
        self.records = parse_records(self.qname, oth, self.header[3])

    @property
    def id(self):
        return self.header[0]

    @id.setter
    def id(self, packet_id):
        self.header[0] = packet_id

    @property
    def qname(self):
        if not self._qname:
            ln = self._bytes[12:].find(b'\x00')
            self.len_name = ln
            name = self._bytes[12:12 + ln]
            return struct.unpack(str(ln) + 's', name)[0]
        return self._qname

    @property
    def ttl(self):
        if len(self.records) > 0:
            return self.records[0].rttl
        return 10000 #ttl for failures

    def __bytes__(self):
        ln = len(self.qname)
        b_header = struct.pack("!HHHHHH", *self.header)
        off = 13 + ln
        b_name = struct.pack(str(ln) + "s", self.qname) + b"\x00" 
        b_rrs = b"".join([bytes(r) for r in self.records])
        return b_header + b_name  + self._bytes[off:off+4] + b_rrs

    def set_ttl(self, ctime, cttl):
        for record in self.records:
            record.rttl = int(cttl - time.time() + ctime)


class RR:
    """Resource record class"""
    def __init__(self, name, data):
        self.rname = name
        self.rtype = get_type(data[2:4])
        self.rclass = get_class(data[4:6])
        self.rttl = struct.unpack('!I', data[6:10])[0]
        self.ln = struct.unpack('!H', data[10:12])[0]
        self.data = data[:12 + self.ln]

    def __bytes__(self):
        b_ttl = struct.pack("!I", self.rttl)
        return self.data[:6] + b_ttl + self.data[10:]


class Server:
    """Server class"""
    def __init__(self, f_addr, sock):
        self.forwarder = f_addr
        self.sock = sock

    def forward(self, data, key):
        pack = ask(data, self.forwarder)
        CACHE[key] = [pack, time.time(), pack.ttl]
        return bytes(pack)

    def request(self, data, client):
        pack = DNSPacket(data)
        key = bytes(pack)[2:].decode()
        if key in CACHE:
            cdata = bytes(CACHE[key][0])
            ctime = CACHE[key][1]
            cttl = CACHE[key][2]
            if time.time() - ctime <= cttl:
                print("From cache")
                reply = DNSPacket(cdata)
                reply.id = pack.header[0]
                reply.set_ttl(ctime, cttl)
                self.sock.sendto(bytes(reply), client)
            else:
                print("Ask forwarder")
                self.sock.sendto(self.forward(data, key), client)
        else:
            print("Ask forwarder")
            self.sock.sendto(self.forward(data, key), client)


def IP(string):
    try:
        parts = string.split(".")
        if len(parts) != 4:
            raise Exception()
        for part in parts:
            if not 0 <= int(part) <= 255:
                raise Exception()
        return string
    except:
        raise ValueError("Wrong IP format")


def parser():
    parser = argparse.ArgumentParser(prog="cacher_dns_server",
                                     description="""Simple forwarding caching dns server
                                                    working on 53 port.
                                                    /Work with root becouse uses shelve/
                                                    If you want clear cache, just remove 
                                                    'cache' file""",
                                     usage="py main.py",
                                     epilog="DimaStark 2016 (c)")
    parser.add_argument("-ip", type=IP, 
                               default="8.8.8.8", 
                               help="Forwarder server IP")
    parser.add_argument("-port", type=int, 
                                 default=53, 
                                 help="Forwarder server port")
    return parser


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    with sock:
        args = parser().parse_args()
        saddr = (args.ip, args.port)
        sock.bind(('', 533))
        while True:
            data, addr = sock.recvfrom(4096)
            serv = Server(saddr, sock)
            proc = Process(target=serv.request, args=(data, addr))
            proc.daemon = True
            proc.start()
    sys.exit(0)


if __name__ == "__main__":
    main()
