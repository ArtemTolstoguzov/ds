import struct
from abc import ABC, abstractmethod
from enum import Enum
from typing import Iterable, Tuple


class InteractionType(Enum):
    REQUEST = 1
    RESPONSE = 2


class CommandType(Enum):
    SEND_MESSAGE = 1
    GET_CLIENTS = 2
    GET_MESSAGES = 3


class Command(ABC):
    @abstractmethod
    def to_bytes(self) -> bytes:
        pass

    @classmethod
    @abstractmethod
    def from_bytes(
        cls, interaction_type: InteractionType, data_bytes: bytes
    ) -> "Command":
        pass


def command_type(_type: CommandType):
    if _type in Protocol._COMMAND_FACTORY:
        raise ValueError(
            f"{_type} is already set for {Protocol._COMMAND_FACTORY[_type]}"
        )

    def decorator(cls):
        Protocol._COMMAND_FACTORY[_type] = cls
        return cls

    return decorator


class Protocol(Command):
    _COMMAND_FACTORY = {}

    def __init__(self, command: CommandType, info: Command, public_key: str, salt: int):
        self.command = command
        self.info = info
        self.public_key = public_key
        self.salt = salt

    def to_bytes(self) -> bytes:
        info_bytes = self.info.to_bytes()
        public_key = self.public_key.encode()
        public_key_length = len(public_key)
        return (
            struct.pack(
                f"!HII{public_key_length}s",
                self.command.value,
                public_key_length,
                self.salt,
                public_key,
            )
            + info_bytes
        )

    @classmethod
    def from_bytes(
        cls, interaction_type: InteractionType, data_bytes: bytes
    ) -> "Protocol":
        current_position = 0
        command_type_number = struct.unpack("!H", data_bytes[current_position:2])[0]
        current_position += 2
        public_key_length, salt = struct.unpack(
            "!II", data_bytes[current_position : current_position + 8]
        )
        current_position += 8
        public_key = struct.unpack(
            f"!{public_key_length}s",
            data_bytes[current_position : current_position + public_key_length],
        )[0]
        current_position += public_key_length
        info_bytes = data_bytes[current_position:]

        command_type = CommandType(command_type_number)
        command_class: Command = cls._COMMAND_FACTORY.get(command_type)
        info = command_class.from_bytes(interaction_type, info_bytes)
        return Protocol(command_type, info, public_key.decode(), salt)


@command_type(CommandType.SEND_MESSAGE)
class SendMessageCommand(Command):
    def __init__(self, message: bytes, recipient):
        self.message = message
        self.recipient = recipient

    def to_bytes(self) -> bytes:
        recipient = self.recipient.encode()
        message_len = len(self.message)
        recipient_len = len(recipient)
        return struct.pack(
            f"!II{recipient_len}s{message_len}s",
            recipient_len,
            message_len,
            recipient,
            self.message,
        )

    @classmethod
    def from_bytes(
        cls, interaction_type: InteractionType, data_bytes
    ) -> "SendMessageCommand":
        recipient_len, message_len = struct.unpack("!II", data_bytes[:8])
        recipient, message = struct.unpack(
            f"!{recipient_len}s{message_len}s", data_bytes[8:]
        )
        return cls(message, recipient.decode())


@command_type(CommandType.GET_CLIENTS)
class GetClientsCommand(Command):
    def __init__(
        self, interaction_type: InteractionType, clients: Iterable[str] = None
    ):
        self._interaction_type = interaction_type
        self.clients = clients or []

    def to_bytes(self) -> bytes:
        if self._interaction_type == InteractionType.REQUEST:
            return b""
        encoded_clients = []
        for client in self.clients:
            client_length = len(client)
            encoded_clients.append(
                struct.pack(f"!I{client_length}s", client_length, client.encode())
            )

        return struct.pack("!I", len(self.clients)) + b"".join(encoded_clients)

    @classmethod
    def from_bytes(
        cls, interaction_type: InteractionType, data_bytes: bytes
    ) -> "GetClientsCommand":
        if interaction_type == InteractionType.REQUEST:
            return cls(interaction_type=InteractionType.REQUEST)
        current_position = 0
        clients_number = struct.unpack(
            "!I", data_bytes[current_position : current_position + 4]
        )[0]
        current_position += 4
        clients = []
        for i in range(clients_number):
            client_length = struct.unpack(
                "!I", data_bytes[current_position : current_position + 4]
            )[0]
            current_position += 4
            client = struct.unpack(
                f"!{client_length}s",
                data_bytes[current_position : current_position + client_length],
            )[0]
            current_position += client_length
            clients.append(client.decode())
        return cls(interaction_type=InteractionType.RESPONSE, clients=clients)


@command_type(CommandType.GET_MESSAGES)
class GetMessagesCommand(Command):
    def __init__(
        self,
        interaction_type: InteractionType,
        messages: Iterable[Tuple[bytes, str]] = None,
    ):
        self.interaction_type = interaction_type
        self.messages = messages or []

    def to_bytes(self) -> bytes:
        if self.interaction_type == InteractionType.REQUEST:
            return b""
        encoded_messages = []
        for message, author in self.messages:
            author = author.encode()
            encoded_messages.append(
                struct.pack(
                    f"!II{len(author)}s{len(message)}s",
                    len(author),
                    len(message),
                    author,
                    message,
                )
            )

        return struct.pack("!I", len(self.messages)) + b"".join(encoded_messages)

    @classmethod
    def from_bytes(
        cls, interaction_type: InteractionType, data_bytes: bytes
    ) -> "GetMessagesCommand":
        if interaction_type == InteractionType.REQUEST:
            return cls(interaction_type=InteractionType.REQUEST)
        current_position = 0
        messages_number = struct.unpack(
            "!I", data_bytes[current_position : current_position + 4]
        )[0]
        current_position += 4
        messages = []
        for i in range(messages_number):
            author_length, message_length = struct.unpack(
                "!II", data_bytes[current_position : current_position + 8]
            )
            current_position += 8
            author, message = struct.unpack(
                f"!{author_length}s{message_length}s",
                data_bytes[
                    current_position : current_position + author_length + message_length
                ],
            )
            current_position += author_length + message_length
            messages.append((message, author.decode()))
        return cls(interaction_type=InteractionType.RESPONSE, messages=messages)
