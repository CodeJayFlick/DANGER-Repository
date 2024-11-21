import socket
from thrift.transport import TSocket, TTransport


class TimeoutChangeableTSnappyFramedTransport(TTransport.TSnappyElasticFramedTransport):
    def __init__(self, underlying_socket, default_buffer_size, max_frame_size):
        super().__init__(underlying_socket, default_buffer_size, max_frame_size)
        self.underlying_socket = underlying_socket

    def setTimeout(self, timeout):
        self.underlying_socket.setTimeout(timeout)

    def getTimeOut(self):
        return self.underlying_socket.getSocket().gettimeout()


class Factory(TTransport.TTransportFactory):
    def __init__(self, default_buffer_size, max_frame_size):
        self.default_buffer_size = default_buffer_size
        self.max_frame_size = max_frame_size

    def getTransport(self, transport):
        if isinstance(transport, TSocket.TSocket):
            return TimeoutChangeableTSnappyFramedTransport(
                transport, self.default_buffer_size, self.max_frame_size)
        else:
            return TSnappyElasticFramedTransport(
                transport, self.default_buffer_size, self.max_frame_size)


# Example usage
factory = Factory(1024, 65536)  # Create a factory with default buffer size of 1024 and max frame size of 65536

transport = factory.getTransport(TSocket.TSocket())  # Get the transport from the factory
