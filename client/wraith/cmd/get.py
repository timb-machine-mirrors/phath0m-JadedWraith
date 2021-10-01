import argparse
import os
import time


def get_command(client, argv):
    parser = argparse.ArgumentParser()

    parser.add_argument("remotefile", help="Remote file name")

    try:
        args = parser.parse_args(argv[1:])
    except SystemExit:
        return
    
    remotefile = args.remotefile
    localfile = "downloads/{0}.{1}".format(os.path.basename(remotefile), int(time.time()))

    if not os.path.isdir("downloads"):
        os.mkdir("downloads")

    client.send_command(6, 0, remotefile.encode("utf-8"))

    with open(localfile, "wb") as fd:

        while True:
            msg = client.recv_message()

            if msg.opcode != 0x10:
                break
            
            fd.write(msg.payload)