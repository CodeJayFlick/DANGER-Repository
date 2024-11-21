import thrift.protocol.TProtocol as TProtocol
from thrift.server import TServerEventHandler
from thrift.transport import TTransport

class SyncServerThriftHandler(TServerEventHandler):
    def __init__(self, service_impl: 'SyncServiceImpl'):
        self.service_impl = service_impl

    def create_context(self, arg0: TProtocol, arg1: TProtocol) -> None:
        return None  # nothing to do here

    def delete_context(self, arg0: ServerContext, arg1: TProtocol, arg2: TProtocol) -> None:
        self.service_impl.handle_client_exit()

    def pre_serve(self) -> None:
        pass  # nothing to do here

    def process_context(self, arg0: ServerContext, arg1: TTransport, arg2: TTransport) -> None:
        pass  # nothing to do here
