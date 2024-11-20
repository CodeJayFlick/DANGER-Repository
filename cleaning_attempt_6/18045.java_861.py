import socket

class TNonblockingSocketWrapper:
    @staticmethod
    def wrap(host: str, port: int) -> socket.socket:
        try:
            return socket.create_connection((host, port))
        except ConnectionRefusedError as e:
            # never happen
            pass
        return None

    @staticmethod
    def wrap(host: str, port: int, timeout: float) -> socket.socket:
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            return sock
        except ConnectionRefusedError as e:
            # never happen
            pass
        return None

    @staticmethod
    def wrap(socket_channel: socket.socket) -> socket.socket:
        try:
            return TNonblockingSocketWrapper.wrap(socket_channel.getpeername()[0], int(socket_channel.getpeername()[1]))
        except ConnectionRefusedError as e:
            # never happen
            pass
        return None

