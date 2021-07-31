def exit_command(client, argv):
    client.disconnect()
    raise SystemExit()
