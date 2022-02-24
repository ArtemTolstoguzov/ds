import json


class Protocol:
    def __init__(self, public_key, command, message='', salt='', to=''):
        self.public_key = public_key
        self.command = command
        self.message = message
        self.salt = salt
        self.to = to

    def to_bytes(self):
        return str.encode(json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4))

    @staticmethod
    def from_bytes(data_bytes):
        data = json.loads(bytes.decode(data_bytes))
        return Protocol(data['public_key'], data['command'], data['message'], data['salt'], data['to'])


class Message:
    def __init__(self, message, sender):
        self.message = message
        self.sender = sender

    def to_bytes(self):
        return str.encode(json.dumps(self, default=lambda o: o.__dict__, sort_keys=True, indent=4))

    @staticmethod
    def from_bytes(data_bytes):
        data = json.loads(bytes.decode(data_bytes))
        return Protocol(data['message'], data['sender'])