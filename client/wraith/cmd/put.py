import argparse
import struct


def put_command(client, argv):
    parser = argparse.ArgumentParser()

    parser.add_argument("localfile", help="Local file to upload")
    parser.add_argument("remotefile", help="Remote file name")

    try:
        args = parser.parse_args(argv[1:])
    except SystemExit:
        return
    
    localfile = args.localfile
    remotefile = args.remotefile

    with open(localfile, "rb") as fd:
        contents = fd.read()

    client.send_command(3, 0, struct.pack("256sI", remotefile.encode("utf-8"), 700) + contents)