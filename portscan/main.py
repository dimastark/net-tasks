# !/usr/bin/python
# -*- coding: utf-8 -*-
import argparse
from multiprocessing import TimeoutError
from portscan import PortScannerAsync


def create_parser():
    parser = argparse.ArgumentParser(prog="PORTSCAN",
                                     description="Scan of ports of remote host",
                                     epilog="DimaStark 2016")
    parser.add_argument("ip", help="host for scan")
    parser.add_argument("start", type=int, help="range start")
    parser.add_argument("end", type=int, help="range end")
    return parser


def main():
    parser = create_parser()
    args = parser.parse_args()
    print("TCP Ports:")
    print_result(args)
    print("UDP Ports:")
    print_result(args, True)


def print_result(args, udp=False):
    res = PortScannerAsync(args.ip, udp).start(args.start, args.end)
    while True:
        try:
            nxt = res.next(timeout=6)
            if nxt:
                print("Port {} open (service: {})".format(*nxt))
        except TimeoutError:
            break
        except StopIteration:
            break


if __name__ == "__main__":
    main()