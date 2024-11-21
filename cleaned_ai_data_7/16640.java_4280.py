import thrift.async as async_client_manager
from thrift.protocol import TProtocolFactory
from thrift.transport import TNonblockingTransport

class TestAsyncClient(async_client_manager.AsyncClient):
    def __init__(self, protocol_factory=None, client_manager=None, transport=None, serial_num=0):
        super().__init__(protocol_factory, client_manager, transport)
        self.serial_num = serial_num

    @property
    def serial_num(self):
        return self._serial_num

    @serial_num.setter
    def serial_num(self, value):
        self._serial_num = value
