# !/usr/bin/python3
# -*- coding: utf-8 -*-
from os.path import basename, splitext
from os import listdir
from random import randint
from argparse import ArgumentParser
import base64
import ssl
import sys
import socket
import getpass


IMGFORMATS = ["jpg", "png", "gif", "bmp", "jpeg"]


def get_auth_details():
    """Get login and password"""
    print("Please write password and login")
    login = input("Login: ")
    password = getpass.getpass("Password: ")
    if not login or not password:
        print("Wrong login or password. Try again.")
        return get_auth_details()
    return login, password


def get_imgs(lst):
    """Get images in lst"""
    for e in lst:
        for form in IMGFORMATS:
            if e.endswith(form):
                yield e


def img_to_base64(path_to_img):
    """Convert image to base64"""
    with open(path_to_img, "rb") as img:
        return base64.standard_b64encode(img.read()).decode()


def format_header(from_who, to_who, bound):
    """Format main fields of the message"""
    return ("From: <{0}>\r\n"
            "To: <{1}>\r\n"
            "Subject: Your pictures\r\n"
            "Content-Type: multipart/related; boundary={2}\r\n"
            "\r\n"
            "--{2}\r\n"
            "Content-Type: text/plain; charset=ascii\r\n\r\n"
            "Some pictures").format(from_who, to_who, bound)


def format_image_attachment(path_to_img):
    """Format attach"""
    ext = splitext(path_to_img)[1][1:]
    name = basename(path_to_img)
    return ('Content-Type: image/{}\r\n'
            'Content-Disposition: attachment; filename="{}"\r\n'
            'Content-Transfer-Encoding: base64\r\n'
            '\r\n{}\r\n').format(ext, name, img_to_base64(path_to_img))


def format_message(boundary, from_who, to_who, attachments):
    """Format message with all needed fields"""
    message = format_header(from_who, to_who, boundary)
    if attachments:
        message += "\r\n--" + boundary + "\r\n"
        for attach in attachments:
            message += format_image_attachment(attach)
            message += "--" + boundary + "\r\n"
    message = message[:-2] + "--\r\n"
    return message


class SMTP:
    out = sys.stderr
    """Smtp class"""
    def __init__(self, server, path, secure):
        self.boundary = str(randint(0, 4815162342))
        self.server = server
        self.sock = socket.socket()
        self.authorities = []
        if secure:
            self.authorities = get_auth_details()
        self.path = path

    @staticmethod
    def check_code(message, error_msg="fail", code=None):
        """Check smtp message code"""
        if message:
            if message[0] == "5":
                SMTP.out.write("\n%s\n" % error_msg)
                sys.exit(1)
            if code:
                if not message.startswith(code):
                    SMTP.out.write("\n%s\n" % error_msg)
                    sys.exit(1)

    def readall(self, check=False, message="fail", code=None):
        """Read all from socket"""
        data = b''
        while True:
            try:
                msg = self.sock.recv(1024)
                if msg:
                    data += msg
            except:
                break
        result = data.decode("utf-8")
        if check:
            SMTP.out.write(result)
            SMTP.check_code(result, message, code)
        return result

    def send_command(self, command):
        SMTP.out.write("\ncom: %s\\r\\n\n\n" % command)
        self.sock.send((command + "\r\n").encode())

    def ehlo(self):
        """Send ehlo"""
        self.send_command("ehlo dimastark")
        self.readall(True, "ehlo error")

    def send(self, to):
        """Send message to 'to'"""
        if self.authorities:
            self.connect_tls()
            self.auth()
            self.pipelining(to)
        else:
            self.connect()
            self.send_data(to)

    def connect_tls(self):
        """Connection by tls"""
        self.sock.settimeout(1.5)
        try:
            self.sock.connect(self.server)
            self.readall(True, "connect fail", "220")
            SMTP.out.write("\nconnect OK\n")
            self.ehlo()
            self.send_command('starttls')
            self.readall(True, "tls connect fail", "220")
            SMTP.out.write('\ntls connect OK\n')
            self.sock = ssl.wrap_socket(self.sock)
            self.ehlo()
        except Exception as e:
            SMTP.out.write("\ntls connection fail\n")
            SMTP.out.write(str(e) + "\n")
            sys.exit(1)

    def auth(self):
        """Authentification"""
        self.send_command("auth login")
        self.readall(True)
        blogin = base64.b64encode(self.authorities[0].encode())
        self.sock.send(blogin + b'\r\n')
        self.readall(True)
        bpass = base64.b64encode(self.authorities[1].encode())
        self.sock.send(bpass + b'\r\n')
        self.readall(True, "auth fail", "235")
        SMTP.out.write("auth OK")

    def pipelining(self, recv_to):
        """Pipelining message"""
        rcpt_to_template = "rcpt to: <{0}>\r\n"
        ppl_c = "mail from: <{0}>\r\n".format(self.authorities[0])
        ppl_c += rcpt_to_template.format(recv_to)
        ppl_c += "data\r\n"
        self.sock.send(ppl_c.encode())
        self.readall(True)
        imgs = list(get_imgs(listdir(self.path)))
        msg = format_message(self.boundary, self.authorities[0], recv_to, imgs)
        self.sock.send(msg.encode())
        self.sock.send(b".\r\n")
        self.readall(True, "something wrong", "250")
        self.send_command("quit")

    def connect(self):
        """Create simple connection"""
        self.sock.settimeout(1.5)
        try:
            self.sock.connect(self.server)
        except:
            SMTP.out.write("\nConnection fail\n")
            sys.exit(1)
        self.readall(True, "connection fail", "220")
        self.ehlo()

    def send_data(self, rcpt):
        """Send data without pipelining"""
        self.send_command("mail from: <%s>" % 'fun@li.ru')
        self.readall(True)
        self.send_command("rcpt to: <%s>" % rcpt)
        self.readall(True)
        self.send_command("data")
        self.readall(True)
        imgs = list(get_imgs(listdir(self.path)))
        data = self.format_message("fun@li.ru", rcpt, imgs)
        # pprint(data)
        self.sock.send(data.encode())
        self.send_command(".")
        self.readall(True, "send fail", "250")

    def __enter__(self):
        return self

    def __exit__(self, et, ev, t):
        self.sock.close()


def parse_args():
    p = ArgumentParser(prog='smtpmime',
                       description='Send pictures by attachment',
                       epilog='DimaStark 2016(c)')
    p.add_argument("email", help="recipient")
    p.add_argument("ip", help="smtp server ip")
    p.add_argument("port", type=int, help="smtp server port")
    p.add_argument("--path", help="Path to images", default=".")
    p.add_argument("--tls", "-s",
                   default=False,
                   help="Connect with tls",
                   action="store_const",
                   const=True)
    return p.parse_args()


if __name__ == "__main__":
    args = parse_args()
    server = args.ip, args.port
    SMTP(server, args.path, secure=args.tls).send(args.email)
