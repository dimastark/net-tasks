#!/usr/bin/python3
import socket
import sys
from argparse import ArgumentParser

from dnsfc.utils import ip, get_logger
from dnsfc.dnscache import Server

LOGGER = get_logger()


def parse_args():
    parser = ArgumentParser(
        prog='dns-fc',
        description='Simple forwarding caching dns server',
        usage='python3 main.py',
        epilog='dimastark 2016 (c)',
    )
    parser.add_argument('--ip', type=ip, default='8.8.8.8', help='Main server ip')
    parser.add_argument('--port', type=int, default=53, help='Main server port')
    parser.add_argument('-p', type=int, default=53, help='Port on which the server will run')
    return parser.parse_args()


def main():
    args = parse_args()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    with sock:
        server_address = (args.ip, args.port)
        try:
            sock.bind(('', args.p))
            server = Server(server_address, sock)
        except Exception as e:
            LOGGER.info('Sorry, there is the error. [PORT: %s]', args.p)
            LOGGER.exception(e)
            sys.exit(1)
        while True:
            data, address = sock.recvfrom(4096)
            server.request(data, address)
    sys.exit(0)
