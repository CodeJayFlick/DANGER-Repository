import thrift.protocol.TProtocol as TProtocol
from thrift.server import ServerContext
from thrift.transport import TTransport

class ClusterInfoServiceThriftHandler:
    def __init__(self, service_impl):
        self.service_impl = service_impl

    def create_context(self, arg0: TProtocol, arg1: TProtocol) -> ServerContext:
        return None  # nothing to do here

    def delete_context(self, context: ServerContext, arg1: TProtocol, arg2: TProtocol):
        self.service_impl.handle_client_exit()

    def pre_serve(self):
        pass  # nothing to do here

    def process_context(self, context: ServerContext, transport1: TTransport, transport2: TTransport):
        pass  # nothing to do here
