import asyncio
from google.protobuf import ByteString as pyByteString
from ghidra_dbg_gadp_protocol_pb2 import GadpValueUtils, GadpConsoleWriteRequest, GadpConsoleWriteReply

class GadpClientTargetConsole:
    def __init__(self):
        self.delegate = None
        self.model = None

    async def write(self, data: bytes) -> asyncio.Future:
        if not self.delegate or not self.delegate.assert_valid():
            return await asyncio.shield(asyncio.sleep(0))  # todo handle this case properly
        
        request = GadpConsoleWriteRequest()
        request.path = GadpValueUtils.make_path(self.get_path())
        request.data = pyByteString(data)
        
        reply_future = self.model.send_checked(request, GadpConsoleWriteReply.DESCRIPTOR.type_number)
        return await asyncio.wait_for(reply_future, timeout=None)

    def get_delegate(self):
        # todo implement this method
        pass

    def get_model(self):
        # todo implement this method
        pass

    def get_path(self):
        # todo implement these methods
        pass
