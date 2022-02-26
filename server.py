import collections
from hashlib import sha256
from socket import AF_INET, SOCK_DGRAM, socket

from message import (CommandType, GetClientsCommand, GetMessagesCommand,
                     InteractionType, Protocol)

SERVER = ("localhost", 5001)


class Server:
    def __init__(self):
        self.clients = set()
        self.sock = socket(AF_INET, SOCK_DGRAM)
        self.sock.bind(SERVER)
        self.messages = collections.defaultdict(list)

    def run(self):
        while True:
            data, addr = self.sock.recvfrom(4096)
            request = Protocol.from_bytes(InteractionType.REQUEST, data)

            self.register_client(request.public_key)

            print("client addr: ", addr, request.command)
            response = None
            if request.command == CommandType.GET_CLIENTS:
                response = Protocol(
                    CommandType.GET_CLIENTS,
                    GetClientsCommand(InteractionType.RESPONSE, self.clients),
                    request.public_key,
                    request.salt,
                )
            elif request.command == CommandType.SEND_MESSAGE:
                self.save_message(request)
                continue
            elif request.command == CommandType.GET_MESSAGES:
                response = self.get_messages(request)
                del self.messages[request.public_key]
            self.sock.sendto(response.to_bytes(), addr)

    def save_message(self, request):
        if sha256(f"{request.info.message}{request.salt}".encode()).hexdigest()[:5] != "00000":
            return  # хэш не совпал, соль не та

        self.messages[request.info.recipient].append(
            (request.info.message, request.public_key)
        )

    def get_messages(self, request):
        return Protocol(
            CommandType.GET_MESSAGES,
            GetMessagesCommand(
                interaction_type=InteractionType.RESPONSE,
                messages=self.messages[request.public_key],
            ),
            request.public_key,
            request.salt,
        )

    def register_client(self, public_key):
        self.clients.add(public_key)


def start():
    server = Server()
    server.run()


if __name__ == "__main__":
    start()
