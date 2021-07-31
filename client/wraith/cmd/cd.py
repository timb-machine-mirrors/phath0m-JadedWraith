import argparse


def cd_command(client, argv):
    parser = argparse.ArgumentParser()

    parser.add_argument("directory", help="New current working directory")

    try:
        args = parser.parse_args(argv[1:])
    except SystemExit:
        return
    
    directory = args.directory

    client.send_command(2, 0, directory.encode("utf-8"))

    resp = client.recv_message()

    if resp.opcode != 0x11:
        print("No such directory")