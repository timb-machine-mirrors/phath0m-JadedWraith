from termcolor import colored

import sys


def print_info(msg):
    sys.stdout.write("[")
    sys.stdout.write(colored("*", "blue"))
    sys.stdout.write("] ")
    sys.stdout.write(msg)
    sys.stdout.write("\n")


def print_error(msg):
    sys.stdout.write("[")
    sys.stdout.write(colored("-", "red"))
    sys.stdout.write("] ")
    sys.stdout.write(msg)
    sys.stdout.write("\n")


def print_success(msg):
    sys.stdout.write("[")
    sys.stdout.write(colored("+", "green"))
    sys.stdout.write("] ")
    sys.stdout.write(msg)
    sys.stdout.write("\n")
