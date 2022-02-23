import os
import socket
import json
from message import Protocol
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

SERVER = ('localhost', 5001)


def generate_keys():
    os.makedirs('./keys')

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open('./keys/private_key.pem', 'wb') as f:
        f.write(pem)

    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open('./keys/public_key.pem', 'wb') as f:
        f.write(pem)


def read_keys():
    with open("./keys/private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None,
            backend=default_backend()
        )

    with open("./keys/public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
            key_file.read(),
            backend=default_backend()
        )

    return private_key, public_key


class Client:
    def __init__(self, private_key, public_key):
        self.private_key = private_key
        self.public_key = public_key
        self.public_key_pem = bytes.decode(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(('localhost', 5002))
        self.clients = []

    def get_clients(self):
        if len(self.clients) == 0:
            self.sock.sendto(
                Protocol(self.public_key_pem, 'get_clients').to_bytes(),
                SERVER
            )
            data, _ = self.sock.recvfrom(4096)
            self.clients = json.loads(bytes.decode(data))

        return self.clients


def start():
    if not os.path.exists('./keys'):
        generate_keys()

    (private_key, public_key) = read_keys()
    client = Client(private_key, public_key)

    while True:
        for i, c in enumerate(client.get_clients()):
            print(i, c)

        cmd = input()


if __name__ == '__main__':
    start()
