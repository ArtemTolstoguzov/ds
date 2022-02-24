import socket
import json
from hashlib import sha256
from message import Protocol, Message
from keys import *
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding


SERVER = ('localhost', 5001)


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

    def send_to_server(self, proto):
        self.sock.sendto(proto.to_bytes(), SERVER)

    def receive_from_server(self):
        pass

    def get_clients(self):
        if len(self.clients) == 0:
            request = Protocol(self.public_key_pem, 'get_clients')
            self.send_to_server(request)

            data, _ = self.sock.recvfrom(4096)
            self.clients = json.loads(bytes.decode(data))

        return self.clients

    def send_message(self, message, to_public_key_pem):
        to_public_key = serialization.load_pem_public_key(to_public_key_pem, backend=default_backend())

        encrypted_message = to_public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        request = Protocol(
            self.public_key_pem,
            'send_message',
            message=encrypted_message,
            salt=self.compute_salt(encrypted_message),
            to=to_public_key_pem
        )
        self.send_to_server(request)

    def get_messages(self):
        request = Protocol(
            self.public_key_pem,
            'get_messages'
        )
        self.send_to_server(request)

        data, _ = self.sock.recvfrom(4096)
        messages = map(lambda o: Message(o['message'], o['sender']), json.loads(bytes.decode(data)))
        decrypted_messages = map(lambda m: (self.private_key.decrypt(
            m.message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ), m.sender), messages)

        return list(decrypted_messages)

    def compute_salt(self, encrypted_message):
        salt = 0
        while sha256(f'{encrypted_message}{salt}'.encode()).hexdigest()[:5] != "00000":
            salt += 1
        return salt


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
