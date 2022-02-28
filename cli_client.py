import os
import sys
from collections import defaultdict

from cryptography.hazmat.primitives import serialization

from client import Client
from keys import generate_keys, read_keys

HELP = """
                           COMMANDS
-------------------------------------------------------------------
sm [i] - send message, i - recipient number
gm     - receive messages
gc     - get clients
help   - print help
-------------------------------------------------------------------
"""
CLIENTS_HEADER = """
                           CLIENTS
-------------------------------------------------------------------
"""
MESSAGES_HEADER = """
                           MESSAGES
-------------------------------------------------------------------
"""
RECIPIENT_STR = """
-------------------------------------------------------------------
Recipient: {}
"""

SERVER_HOST, SERVER_PORT = sys.argv[1].split(":")
SERVER_PORT = int(SERVER_PORT)
PORT = int(sys.argv[2])


def print_clients(client: Client):
    print(CLIENTS_HEADER)

    for index, client_name in enumerate(client.get_clients()):
        client_str = f"{index}: {client_name[27:91]}"
        if client_name == client.public_key_pem:
            client_str += " SELF"
        print(client_str)
    print("-------------------------------------------------------------------")


def send_message(client: Client, recipient_index: int):
    recipient = client.clients[recipient_index]
    print(RECIPIENT_STR.format(recipient[27:91]))
    print("Type your message:")
    message = input()
    print("POW-process...")
    client.send_message(message, recipient)
    print("Message sent!")
    print("-------------------------------------------------------------------")


def get_messages(client: Client):
    messages = client.get_messages()
    print(MESSAGES_HEADER)
    messages_repr = defaultdict(list)
    for message in filter(lambda m: m.verified, messages):
        public_key_pem = bytes.decode(
            message.author_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        messages_repr[public_key_pem[27:91]].append(message.message.decode())
    for author, messages in messages_repr.items():
        print(f"Author: {author}")
        print("Messages:")
        for message in messages:
            print(message)
        print("-----------------------")


def cli_run():
    if not os.path.exists("./keys"):
        os.makedirs("./keys")
    if not os.path.exists(f"./keys/{PORT}"):
        generate_keys(str(PORT))

    (private_key, public_key) = read_keys(str(PORT))
    client = Client(private_key, public_key, (SERVER_HOST, SERVER_PORT), PORT)
    print(HELP)
    print_clients(client)
    while True:
        cmd = input().split()

        if cmd[0] == "sm":
            send_message(client, int(cmd[1]))
        elif cmd[0] == "gm":
            get_messages(client)
        elif cmd[0] == "gc":
            print_clients(client)
        elif cmd[0] == "help":
            print(HELP)


if __name__ == "__main__":
    cli_run()
