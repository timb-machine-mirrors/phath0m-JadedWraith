from .cd import cd_command
from .exit import exit_command
from .put import put_command

COMMANDS = [
    ("cd", cd_command),
    ("exit", exit_command),
    ("put", put_command)
]


def register_commands(client):
    for name, handler in COMMANDS:
        client.add_command(name, handler)
