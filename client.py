import sys
from hashlib import sha256
from socket import AF_INET, SOCK_DGRAM, socket

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from message import (CommandType, GetClientsCommand, GetMessagesCommand,
                     InteractionType, Protocol, SendMessageCommand)

SERVER = ("localhost", 5001)
CLIENT = ("localhost", int(sys.argv[1]))


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
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind(CLIENT)
        self.clients = []

    def send_to_server(self, proto):
        self.sock.sendto(proto.to_bytes(), SERVER)

    def receive_from_server(self) -> Protocol:
        data, _ = self.sock.recvfrom(4096)
        return Protocol.from_bytes(InteractionType.RESPONSE, data)

    def get_clients(self):
        request = Protocol(
            CommandType.GET_CLIENTS,
            GetClientsCommand(InteractionType.REQUEST),
            self.public_key_pem,
            12,  # TODO
        )
        self.send_to_server(request)

        response = self.receive_from_server()
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
            self.compute_salt(encrypted_message),
        )
        self.send_to_server(request)

    def get_messages(self):
        request = Protocol(
            CommandType.GET_MESSAGES,
            GetMessagesCommand(InteractionType.REQUEST),
            self.public_key_pem,
            12,  # TODO
        )
        self.send_to_server(request)

        response = self.receive_from_server()
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
