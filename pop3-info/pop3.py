# !/usr/bin/python3
# -*- coding: utf-8 -*-
import sys
import socket
import ssl
import re
from pprint import pprint
from email.header import decode_header


def parser():
    """Create argument parser"""
    from argparse import ArgumentParser
    p = ArgumentParser(description="Info about mail by pop3",
                       epilog="DimaStark 2016 (c)")
    p.add_argument('ip', help="Server ip")
    p.add_argument("--port", "-p", type=int, default=995, help="Server port")
    p.add_argument("login", help="Account login")
    p.add_argument("password", help="Account password")
    p.add_argument("--start", "-s", default=1, type=int)
    p.add_argument("--end", "-e", default=2, type=int)
    return p


class MailParser:
    """Parser mail headers and other date"""
    TO = re.compile("To:\s(.+)", re.IGNORECASE)
    FROM = re.compile("From:\s(.+)", re.IGNORECASE)
    SUBJECT = re.compile("Subject:\s(.+)", re.IGNORECASE)
    DATE = re.compile("Date:\s(.+)", re.IGNORECASE)
    SIZE = re.compile("\+OK\s(\d+)\s")
    BOUNDARY = re.compile("boundary=(.*?)[\n;]")
    FILENAME = re.compile('filename="(.*)"')
    BASE64 = re.compile('\n([A-z0-9+/\n=\s]+)\n')

    def parse(field_name, string):
        """Parse field"""
        regex = getattr(MailParser, field_name.upper())
        finds =  regex.findall(string)
        if len(finds) > 0:
            return finds[0]

    def parse_head(data):
        """Parse header"""
        dec = decode_header(data)
        f_dec = ""
        for i in range(len(dec)):
            if dec[i][1]:
                f_dec += dec[i][0].decode(dec[i][1])
            else:
                if type(dec[i][0]) == type('str'):
                    f_dec += dec[i][0]
                else:
                    f_dec += dec[i][0].decode()
        return f_dec

    def parse_info(data):
        """Parse main fields"""
        flags = [True, True, True]
        fields = ["To", "Date", "Size"]
        res = {'Size': 'unknown', 'To': '', 'Date': ''}
        lines = str(data).split('\\r\\n')
        indexer = 0
        while indexer < len(lines) and any(flags):
            line = lines[indexer]
            indexer += 1
            for i, field in enumerate(fields):
                if flags[i]:
                    parsed = MailParser.parse(field, line)
                    if parsed:
                        res[field] = parsed
                        flags[i] = False
        return res

    def parse_from(data):
        """Parse FROM"""
        flag = False
        from_who = ""
        fields = ["To", "Subject", "Date", "Content-Type"]
        for line in str(data).split('\\r\\n'):
            if flag:
                if 'To' in line \
                or 'Subject' in line \
                or 'Date' in line \
                or 'Content-Type' in line:
                    break
                else:
                    from_who += line
            else:
                sub = MailParser.parse("from", line)
                if sub:
                    flag = True
                    from_who += sub
        return from_who.replace('\\t', '')

    def parse_subject(data):
        """Parse subject of data"""
        flag = False
        subj = ""
        for line in str(data).split('\\r\\n'):
            if flag:
                if 'From' in line \
                or 'To' in line \
                or 'Date' in line \
                or 'Content-Type' in line:
                    break
                else:
                    if '=?' in line:
                        subj += line
            else:
                sub = MailParser.parse("subject", line)
                if sub:
                    flag = True
                    subj += sub
        return subj.replace('\\t', '')

    def parse_attachments(data):
        atts_sizes = dict()
        b = MailParser.BOUNDARY.findall(data.decode())
        if len(b) >= 1:
            b = b[-1].replace('"', '').replace("'", '')
            for line in data.decode().split(b):
                name = MailParser.parse("filename", line)
                if name:
                    f_name = str(name)
                    s = MailParser.parse("base64", line)
                    if s:
                        atts_sizes[f_name] = str((len(s)*6)//8) + ' bytes'
                    else:
                        atts_sizes[f_name] = 'Х'
        return atts_sizes


def readall(sock):
    """Read all data from socket"""
    msg = b''
    while True:
        try:
            temp = sock.recv(1024)
            if not temp: break
            msg += temp
        except: break
    return msg


class POP3:
    """POP3 class"""
    def __init__(self, ):
        self.sock = ssl.wrap_socket(socket.socket())

    def connect(self, ip, port):
        self.sock.settimeout(1)
        try:
            self.sock.connect((ip, port))
            msg = readall(self.sock).decode()
            sys.stderr.write(msg)
            if msg[:3] != '+OK':
                raise Exception()
        except:
            raise Exception("Connection FAIL")

    def authorization(self, login, password):
        blogin = ('user %s\r\n' % login).encode()
        bpassw = ('pass %s\r\n' % password).encode()
        try:
            for auth_data in [blogin, bpassw]:
                self.sock.send(auth_data)
                msg = readall(self.sock).decode()
                sys.stderr.write(msg)
                if msg[:3] != "+OK":
                    raise Exception()
        except:
            raise Exception('Authorization FAIL')

    def stat(self):
        self.sock.send(b"stat\r\n")
        msg = readall(self.sock).decode()
        sys.stderr.write(msg)
        return int(MailParser.parse("size", msg))

    def get_mail(self, start, end):
        count = self.stat()
        end = min(end, count)
        for cur in range(start, end):
            try:
                self.sock.send(("retr %s\r\n" % cur).encode())
                msg = readall(self.sock)
                sbj = MailParser.parse_subject(msg)
                fr = MailParser.parse_from(msg)
                general_info = MailParser.parse_info(msg)
                yield cur, {'Subject: ': MailParser.parse_head(sbj),
                            'From: ': MailParser.parse_head(fr),
                            'Size: ': general_info['Size'] + ' bytes',
                            'To: ': MailParser.parse_head(general_info['To']),
                            'Date: ': general_info['Date'],
                            'Attachments: ': MailParser.parse_attachments(msg)}
            except:
                yield cur, "Something wrong"
                continue

    def __exit__(self, a, b, c):
        self.sock.close()

    def __enter__(self):
        return self


def main():
    args = parser().parse_args()
    start, end = args.start, args.end
    with POP3() as p:
        try:
            print("Connect...\n")
            p.connect(args.ip, args.port)
            print("Connect OK\n")
            print("Authorization...\n")
            p.authorization(args.login, args.password) 
            print("Authorization OK\n")
            print("Get mail...({}-{})\n".format(start, end))
            for i, mail in p.get_mail(start, end):
                print("Mail %s:" % i)
                pprint(mail)
                print("\n")
        except Exception as e:
            print(e)
            print("FAIL\n")



if __name__ == "__main__":
    main()