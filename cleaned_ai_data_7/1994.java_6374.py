import socket
from abc import ABCMeta, abstractmethod


class AbstractGadpServer(metaclass=ABCMeta):
    LISTENING_ON = "GADP Server listening on "

    def __init__(self, model: 'DebuggerObjectModel', addr: tuple) -> None:
        self.model = model
        super().__init__(*addr)
        print(self.LISTENING_ON + str(addr))
        self.model.add_model_listener(self)

    @abstractmethod
    def check_acceptable(self, sock: socket.socket) -> bool:
        pass

    @abstractmethod
    def new_handler(self, sock: socket.socket) -> 'GadpClientHandler':
        pass


class DebuggerObjectModel:
    def __init__(self):
        self.address_spaces = {}

    def get_address_space(self, space_name: str) -> dict or None:
        return self.address_spaces.get(space_name)

    def add_model_listener(self, listener: object) -> None:
        # TO DO
        pass

    def close(self) -> None:
        print("Model closed")
        # TO DO


class GadpClientHandler:
    def __init__(self, server: 'AbstractGadpServer', sock: socket.socket):
        self.server = server
        self.sock = sock


def get_address_range(self, range: dict or None) -> tuple:
    if not range:
        return (None, None)

    space_name = range.get('space')
    offset = int(range.get('offset'))
    extend = int(range.get('extend'))

    address_space = self.model.get_address_space(space_name)
    min_addr = address_space['min']
    max_addr = min_addr + extend

    return (min_addr, max_addr)


def model_closed(self, reason: str) -> None:
    print("Model closed: " + reason)

    if self.exit_on_closed:
        exit(0)


class AddressRangeImpl(tuple):
    pass


# TO DO
