from socket import *
import json
from hashlib import sha256
from message import Protocol, Message


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
            return #хэш не совпал
         #todo сохраняем сообщеньку


    def get_messages(self, request):
         #todo отдаем список сообщений по request.public_key
        pass

    def register_client(self, public_key):
        self.clients.add(public_key)


def start():
    server = Server()
    server.run()


if __name__ == '__main__':
    start()
