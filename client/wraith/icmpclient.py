import hashlib
import os
import socket
import struct
import time

def carry_around_add(a, b):
    c = a + b
    return (c & 0xffff) + (c >> 16)


def checksum(msg):
    s = 0
    for i in range(0, len(msg), 2):
        w = msg[i] + (msg[i + 1] << 8)
        s = carry_around_add(s, w)
    return ~s & 0xffff


def ip2int(addr):
    return struct.unpack("!I", socket.inet_aton(addr))[0]


class IcmpClient:

    def __init__(self, password, modulo=60, skew=-1):
        self._password = password
        self._skew = skew
        self._modulo = modulo

    def calculate_wakeup_key(self, salt):
        now = int(time.time()) + self._skew

        if self._modulo != 0:
            minute = now - (now % self._modulo)
        else:
            minute = 0

        sha256 = hashlib.sha256()
        sha256.update(salt + self._password.encode("utf-8"))
        return sha256.digest()

    def calculate_xor_key(self):
        magic = self._password.encode("utf-8")

        sha256 = hashlib.sha256()
        sha256.update(magic)

        c1, c2, c3, c4 = struct.unpack("IIII", sha256.digest()[0:16])

        return c1 ^ c2 ^ c3 ^ c4

    def send_packet(self, target, callback_ip, callback_port):
        with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp")) as sock:
            hdr = struct.pack("bbHHh", 8, 0, 0, 0x01, 1)
            salt = os.urandom(16)
            magic = self.calculate_wakeup_key(salt)
            xor_key = self.calculate_xor_key()
            ip_enc = ip2int(callback_ip) ^ xor_key
            port_enc = (callback_port ^ xor_key) & 0xFFFF
            callback_info = struct.pack("IH", ip_enc, port_enc)
            packet_checksum = checksum(hdr + salt + magic + callback_info)
            hdr = struct.pack("bbHHh", 8, 0, packet_checksum, 0x01, 1)
            sock.sendto(hdr + salt + magic + callback_info, (target, 1))
