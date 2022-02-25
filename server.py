from socket import *
import json
import collections
from hashlib import sha256
from message import Protocol, Message


SERVER = ('localhost', 5001)


class Server:
    def __init__(self):
        self.clients = set()
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind(SERVER)
        self.messages = collections.defaultdict(list)

    def run(self):
        while True:
            data, addr = self.sock.recvfrom(4096)
            request = Protocol.from_bytes(data)

            self.register_client(request.public_key)

            print('client addr: ', addr, request.command)
            response = None
            if request.command == 'get_clients':
                response = list(self.clients)
            elif request.command == 'send_message':
                self.save_message(request)
                return
            elif request.command == 'get_messages':
                response = self.get_messages(request)

            self.sock.sendto(str.encode(json.dumps(response)), addr)

    def save_message(self, request):
        if sha256(f'{request.message}{request.salt}'.encode()).hexdigest()[:5] != "00000":
            return #хэш не совпал, соль не та

        self.messages[request.to].append((request.message, request.public_key))

    def get_messages(self, request):
         return list(map(lambda m: Message(m[0], m[1]), self.messages[request.public_key]))


    def register_client(self, public_key):
        self.clients.add(public_key)


def start():
    server = Server()
    server.run()


if __name__ == '__main__':
    start()
