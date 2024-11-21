import socket

class TimeoutChangeableTransport:
    def set_timeout(self, timeout: int):
        pass  # implement me!

    def get_time_out(self) -> int:
        raise socket.timeout
