#!/usr/bin/python3
""" SNTP LIAR SERVER """
import logging
import socket
from argparse import ArgumentParser, RawTextHelpFormatter
from multiprocessing import Process
from datetime import datetime
import sys
import time
import struct


def get_logger():
    """ Get root logger for program """
    logging.basicConfig(level=logging.INFO)
    log = logging.getLogger('dns-fc')
    return log


PACKET_FORMAT = struct.Struct('!BBBBIIIQQQQ')
SEVENTY_YEARS_IN_SECONDS = (datetime(1970, 1, 1) - datetime(1900, 1, 1)).total_seconds()
LOGGER = get_logger()


def parse_args():
    """ Parse arguments from console """
    parser = ArgumentParser(
        prog='sntp-liar',
        description='This program lies to stupid sntp clients.\n'
                    'NYEH-HEH-HEH\n'
                    'Work on 123/udp.\n',
        usage='sntp_liar',
        epilog='dimastark 2016',
        formatter_class=RawTextHelpFormatter,
    )
    parser.add_argument(
        'shift', type=int,
        help='The shift to which you want to lie',
        default=0,
    )
    parser.add_argument(
        '--port', type=int,
        help='sntp-liar port',
        default=123,
    )
    return parser.parse_args()


def calculate_time(shift):
    """ Calculate current time """
    return int(time.time() + SEVENTY_YEARS_IN_SECONDS + shift) * 2**32


def client_work(sock, request, address, shift):
    """Work with listen sock. Response >> sock"""
    response = make_response(request, shift)
    sock.sendto(response, address)


def make_response(request, shift):
    """Make response by request"""
    if PACKET_FORMAT.size == len(request):
        data = PACKET_FORMAT.unpack(request)
        return PACKET_FORMAT.pack(
            36, 1, 0, 0, 0, 0, 0, 0,
            data[10], calculate_time(shift),
            calculate_time(shift),
        )


def main():
    args = parse_args()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.bind(('', args.port))
        except Exception as e:
            LOGGER.info('Sorry port %s is already used or you don`t have rights', args.port)
            LOGGER.exception(e)
            sys.exit(1)
        while True:
            request, address = sock.recvfrom(1024)
            process = Process(
                target=client_work,
                args=(sock, request, address, args.shift),
            )
            process.daemon = True
            process.start()
