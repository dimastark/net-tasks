# coding=utf-8
#!/usr/bin/env python3


from random import randint
import socket
import re
from struct import pack, unpack


REFERRAL_RE = re.compile(r'refer:[^\w]+([\w\.]+)')
AS_RE = re.compile(r'origin:[^\w]+(\w+)')
COUNTRY_RE = re.compile(r'country:[^\w]+(\w+)')
ICMP = socket.getprotobyname('icmp')
UDP = socket.getprotobyname('udp')
RAW = socket.IPPROTO_RAW


class WhoisRecord:
    """Class for whois record"""
    def __init__(self, ip):
        self.ip = ip
        self.name = get_hostname(ip)
        self.data = whois(ip)
        self.refer = REFERRAL_RE.search(self.data).groups()[0]
        self.asys = AS_RE.search(self.data)
        self.country = COUNTRY_RE.search(self.data)
        self.init_servers()
        self.get_all_data()

    def init_servers(self):
        """Get all possible servers for one record:
           -referal
           -server for domain
        """
        parts = self.name.split(".")
        high_domain = parts[-1]
        self.servers = [self.refer,  # add refer to all servers
                        "whois.nic." + high_domain,  # possible server
                        "whois." + high_domain]  # add domain whois servers
        if len(parts) > 3:
            mid_domain = parts[-2]
            self.servers.append("whois." + mid_domain)
            self.servers.append("whois.nic." + mid_domain)

    def get_all_data(self):
        """Get country, as, and name"""
        infos = [(AS_RE.search(self.data), COUNTRY_RE.search(self.data))]
        for server in self.servers:
            try:
                by_nm = whois(self.name, addr=(server, 43))
                by_ip = whois(self.ip, addr=(server, 43))
                infos.append((AS_RE.search(by_nm), COUNTRY_RE.search(by_nm)))
                infos.append((AS_RE.search(by_ip), COUNTRY_RE.search(by_ip)))
            except:
                continue
        countries = [i[1].groups()[0] for i in infos if i[1]]
        a_systems = [i[0].groups()[0] for i in infos if i[0]]
        self.asys = max(set(a_systems), key=a_systems.count)
        self.country = max(set(countries), key=countries.count)

    def __str__(self):
        """String representation"""
        to_str = []
        if self.name:
            to_str.append(self.name)
        if self.asys:
            to_str.append(self.asys)
        if self.country:
            to_str.append(self.country)
        return "[" + ", ".join([self.name, self.asys, self.country]) + "]"


def get_hostname(ip):
    """Return domain name or ''"""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return ip


def get_my_ip():
    """Return ip for your pc"""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.connect(("gmail.com", 80))
            return sock.getsockname()[0]
        except:
            return "127.0.0.1"


def traceroute(target, maxttl=13, timeout=1):
    """Python3 traceroute to target with 'timeout' and 'maxttl'"""
    port = 54354
    s_addr = get_my_ip(), randint(10000, 65535)
    d_addr = target, port
    for ttl in range(1, maxttl + 1):
        recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, ICMP)
        send = socket.socket(socket.AF_INET, socket.SOCK_RAW, RAW)
        recv.settimeout(timeout)
        recv.bind(("", port))
        send.sendto(create_packet(ttl, s_addr, d_addr), d_addr)
        nxt_addr = "*"
        try:
            with recv, send:
                packet, nxt_addr = recv.recvfrom(512)
                icmp_type, icmp_code = parse_icmp(packet)
                if icmp_type == 0 and icmp_code == 0:
                    break
        except socket.error:
            pass
        yield ttl, nxt_addr[0]


def create_packet(ttl, source, dest):
    """Create packet with needed ttl"""
    s_ip, s_port = source
    d_ip, d_port = dest
    structure = '!BBHHHBBH4s4sHHHH'
    to_pack = [("ihl_version", 69),
               ("tos", 0),
               ("total_len", 0),
               ("id", randint(0, 65535)),
               ("fragmentation_off", 0),
               ("ttl", ttl),
               ("proto", socket.IPPROTO_UDP),
               ("check", 0),
               ("saddr", socket.inet_aton(s_ip)),
               ("daddr", socket.inet_aton(d_ip)),
               ("s_port", s_port),
               ("d_port", d_port),
               ("udp_len", 8),
               ("checksum", 0)]
    return pack(structure, *[i[1] for i in to_pack])


def parse_icmp(packet):
    """Parse icmp packet and return type and code"""
    icmp_part = packet[20:22]
    icmp_type, icmp_code = unpack("!BB", icmp_part)
    return icmp_type, icmp_code


def whois(target, addr=("whois.iana.org", 43)):
    """Whois request to 'addr'"""
    parts = []
    sock = socket.create_connection(addr)
    sock.sendall(target.encode() + b"\r\n")
    while True:
        buf = sock.recv(4096)
        if not buf:
            break
        parts.append(buf.decode('utf-8'))
    return "".join(parts)


def is_private(ip):
    """Check ip is private"""
    import ipaddress
    return ipaddress.ip_address(ip).is_private


def work_with_record(record):
    """Work with concrete ip address"""
    if is_private(record[1]):
        ans = "[Is private]"
    else:
        ans = str(WhoisRecord(record[1]))
    return ans


def main(targets, maxttl, timeout):
    """Main entry of application"""
    count = 0
    for target in targets:
        print("[{0}]:".format(target))
        for record in traceroute(target, maxttl=maxttl, timeout=timeout):
            ttl, ip = record
            if ip != "*":
                count = 0
                additional = work_with_record(record)
                print("{0}: {1} - {2}".format(ttl, ip, additional))
            else:
                count += 1
                if count < 2:
                    print("{0}: {1}".format(ttl, ip))
                elif count == 2:
                    print("...")


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(prog="traceras",
                                     description="""Tracing all ips in arguments.
                                     Usage: traceras.py 1.1.1.1 2.2.2.2""",
                                     epilog="(c) Dimastark 2016")
    parser.add_argument("targets", nargs='+',
                        help="All targets to tracing")
    parser.add_argument("-m", "--maxttl",
                        type=int,
                        help="Max ttl for tracing",
                        default=20)
    parser.add_argument("-t", "--timeout", type=int,
                        help="Timeout to tracing",
                        default=1)
    args = parser.parse_args()
    ips = [socket.gethostbyname(i) for i in args.targets]
    main(ips, args.maxttl, args.timeout)
