import json
import socket
import sys
from hashlib import sha256

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from keys import *
from message import SendMessageCommand, Protocol, CommandType, EmptyCommand, GetClientsCommand, InteractionType, \
    GetMessagesCommand

SERVER = ("localhost", 5001)
CLIENT = ("localhost", 9000)


class Client:
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key
        self.public_key_pem = bytes.decode(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(CLIENT)
        self.clients = []

    def send_to_server(self, proto):
        self.sock.sendto(proto.to_bytes(), SERVER)

    def receive_from_server(self):
        pass

    def get_clients(self):
        request = Protocol(
            CommandType.GET_CLIENTS,
            GetClientsCommand(InteractionType.REQUEST),
            self.public_key_pem,
            12  # TODO
        )
        self.send_to_server(request)

        data, _ = self.sock.recvfrom(4096)
        response = Protocol.from_bytes(InteractionType.RESPONSE, data)
        self.clients = list(
            filter(lambda c: c != self.public_key_pem, response.info.clients)
        )
        self.clients = list(response.info.clients)

        return self.clients

    def send_message(self, message: str, recipient_public_key: str):
        recipient_public_key_pem = serialization.load_pem_public_key(
            recipient_public_key.encode(), backend=default_backend()
        )
        enc = message.encode()

        encrypted_message = recipient_public_key_pem.encrypt(
                enc,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

        request = Protocol(
            CommandType.SEND_MESSAGE,
            SendMessageCommand(encrypted_message, recipient_public_key),
            self.public_key_pem,
            self.compute_salt(encrypted_message)
        )
        self.send_to_server(request)

    def get_messages(self):
        request = Protocol(
            CommandType.GET_MESSAGES,
            GetMessagesCommand(InteractionType.REQUEST),
            self.public_key_pem,
            12  # TODO
        )
        self.send_to_server(request)

        data, _ = self.sock.recvfrom(4096)
        response = Protocol.from_bytes(interaction_type=InteractionType.RESPONSE, data_bytes=data)
        decrypted_messages = map(
            lambda m: (
                self.private_key.decrypt(
                    m[0],
                    padding.OAEP(
                        mgf=padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None,
                    ),
                ).decode(),
                m[1],
            ),
            response.info.messages,
        )

        return list(decrypted_messages)

    def compute_salt(self, encrypted_message):
        salt = 0
        while sha256(f"{encrypted_message}{salt}".encode()).hexdigest()[:5] != "00000":
            salt += 1
        return salt


def cli_run():
    if not os.path.exists("./keys"):
        generate_keys()

    (private_key, public_key) = read_keys()
    client = Client(private_key, public_key)

    while True:
        print("                             CLIENTS")
        print("-------------------------------------------------------------------")
        for i, c in enumerate(client.get_clients()):
            print(f"{i}: {c[27:91]}")
        print("-------------------------------------------------------------------")

        print("")
        print("                             COMMANDS")
        print("-------------------------------------------------------------------")
        print("sm [i] - send message, i - recipient number")
        print("gs     - receive messages")
        print("-------------------------------------------------------------------")
        print("")

        cmd = input().split()

        if cmd[0] == "sm":
            print("-------------------------------------------------------------------")
            to_public_key_pem = client.clients[int(cmd[1])]
            print(f"Recipient: {to_public_key_pem[27:91]}")
            print("Message:")
            message = input()
            print("POW-process...")
            client.send_message(message, to_public_key_pem)
            print("Message sent!")
        elif cmd[0] == "gs":
            print("-------------------------------------------------------------------")
            messages = client.get_messages()
            for message in messages:
                print(f"Sender: {message[1][27:91]}")
                print("Message:")
                print(message[0])
                print("-----------------------")
        elif cmd[0] == "gc":
            for i, c in enumerate(client.get_clients()):
                print(f"{i}: {c[27:91]}")


if __name__ == "__main__":
    cli_run()
