from Crypto.Cipher import Salsa20
from collections import namedtuple
import os
import socket
import struct
import sys
import importlib.util


WraithMsg = namedtuple("WraithMsg", ["opcode", "arg", "payload_size", "payload"])


class S20Client:
    def __init__(self, secret):
        self.send_cipher = Salsa20.new(key=secret)
        self.recv_cipher = Salsa20.new(key=secret)

    def wrap_socket(self, sock):
        self.sock = sock
        self.sock.sendall(self.send_cipher.nonce)
        self.sock.sendall(self.recv_cipher.nonce)

    def disconnect(self):
        self.sock.close()

    def sendall(self, contents):
        self.sock.sendall(self.send_cipher.encrypt(contents))

    def send_command(self, wraith_command, arg=0, payload=None):
        payload_len = len(payload) if payload is not None else 0

        cmd = struct.pack("<BII", wraith_command, arg, payload_len);
        self.sendall(cmd)

        if payload_len > 0:
            self.sendall(payload)

    def recv(self, length):
        data = b''

        while len(data) < length:
            chunk = self.sock.recv(length - len(data))
            if not chunk:
                return None
            data += chunk

        return self.recv_cipher.decrypt(data)

    def recv_message(self):
        msg = self.recv(9)

        opcode, arg, payload_len = struct.unpack("<BII", msg)

        if payload_len > 0:
            payload = self.recv(payload_len)
        else:
            payload = None

        return WraithMsg(opcode, arg, payload_len, payload)


def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]