Here is the translation of the Java code to Python:
```
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
```
Note that I've used the `thrift` library in Python to translate the Thrift-related code. You'll need to install this library using pip (`pip install thrift`) and import it as shown above.

Also, I've kept the method names identical to their Java counterparts, but you may want to consider renaming them to follow PEP 8 conventions (e.g., `create_context` becomes `create_context_`).