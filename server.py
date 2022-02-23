from socket import *
import json
from message import Protocol

SERVER = ('localhost', 5001)


class Server:
    def __init__(self):
        self.clients = set()
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind(SERVER)

    def run(self):
        while True:
            data, addr = self.sock.recvfrom(4096)
            request = Protocol.from_bytes(data)
            self.register_client(request.public_key)
            print('client addr: ', addr, request)
            response = None
            if request.command == 'get_clients':
                response = str.encode(json.dumps(list(self.clients)))

            self.sock.sendto(response, addr)

    def register_client(self, public_key):
        self.clients.add(public_key)


def start():
    server = Server()
    server.run()


if __name__ == '__main__':
    start()
