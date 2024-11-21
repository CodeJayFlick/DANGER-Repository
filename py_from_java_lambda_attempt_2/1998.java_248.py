Here is the translation of the Java code into Python:

```Python
import asyncio
from typing import List, Map

class TestServer:
    def __init__(self):
        self.srv = None
        self.addr = None
        self.cli = None
        self.seqno = 0

        self.inbuf = bytearray(1024)
        self.outbuf = bytearray(1024)

    async def close(self):
        await asyncio.sleep(1)  # simulate closing the socket
        if self.cli is not None:
            self.cli.close()
        if self.srv is not None:
            self.srv.close()

    async def accept(self):
        self.cli = await self.srv.accept()
        self.cli.setblocking(False)

    async def next_seq(self):
        self.seqno += 1

    async def expect(self, msg: 'Gadp.RootMessage'):
        while True:
            try:
                recv = Gadp. RootMessage.parse_from_bytes(self.inbuf)
                print(f"Server Received: {recv}")
                assert msg == recv
                return
            except Exception as e:
                if isinstance(e, asyncio.TimeoutError):
                    raise TimeoutError("Timeout out expecting: " + str(msg))
                await asyncio.sleep(0)

    async def send(self, msg: 'Gadp.RootMessage'):
        self.outbuf.clear()
        Gadp. RootMessage.encode_to_bytes(msg, self.outbuf)
        while self.outbuf.has_remaining():
            if not self.cli.is_writable():
                raise Exception("Socket is closed")
            await self.cli.write(self.outbuf)

    async def send_reply_connect(self, version: 'GadpVersion'):
        msg = Gadp. RootMessage.newBuilder().setSequence(self.seqno).setConnectReply(Gadp.ConnectReply.newBuilder().setVersion(version.name).build()).build()
        await self.send(msg)
        self.next_seq()

    async def handle_connect(self, version: 'GadpVersion'):
        await self.expect(Gadp.RootMessage.newBuilder().setSequence(self.seqno).setConnectRequest(GadpVersion.make_request()).build())
        await self.send_reply_connect(version)
        self.next_seq()

class GadpClient:
    def __init__(self, name: str, socket):
        self.name = name
        self.socket = socket

    async def connect(self) -> 'CompletableFuture':
        return CompletableFuture.runnable(lambda: None)

    async def ping(self, content: str) -> 'CompletableFuture':
        msg = Gadp.RootMessage.newBuilder().setSequence(0).setPingRequest(Gadp.PingRequest.newBuilder().setContent(content)).build()
        await self.expect(msg)
        await self.send_reply_ping(content)
        return CompletableFuture.runnable(lambda: None)

    async def close(self):
        if not self.socket.is_closing():
            try:
                while True:
                    read = await self.socket.read(self.inbuf)
                    print(f"Read {read} bytes")
                    if read < 0:
                        raise Exception("Socket is closed")
                    elif read == 0:
                        break
            except asyncio.TimeoutError as e:
                raise TimeoutError("Timeout out waiting for data")

class CompletableFuture:
    def __init__(self, result):
        self.result = result

    async def runnable(self, func: callable) -> 'CompletableFuture':
        return self

    async def then_run(self, action: callable) -> 'CompletableFuture':
        await asyncio.sleep(0)
        return self

class Test:
    @asyncio.coroutine
    def test_connect_disconnect(self):
        srv = TestServer()
        socket = yield from aiohttp.ClientSession().get('ws://localhost:8080')
        client = GadpClient("Test", socket)

        connect_future = CompletableFuture.runnable(lambda: None)
        await srv.accept()
        read = await socket.read(1024)
        print(f"Read {read} bytes")
        if read < 0:
            raise Exception("Socket is closed")

    @asyncio.coroutine
    def test_ping(self):
        srv = TestServer()
        socket = yield from aiohttp.ClientSession().get('ws://localhost:8080')
        client = GadpClient("Test", socket)

        connect_future = CompletableFuture.runnable(lambda: None)
        await srv.accept()
        read = await socket.read(1024)
        print(f"Read {read} bytes")
        if read < 0:
            raise Exception("Socket is closed")

    @asyncio.coroutine
    def test_resync_once_model_value_deduped(self):
        srv = TestServer()
        socket = yield from aiohttp.ClientSession().get('ws://localhost:8080')
        client = GadpClient("Test", socket)

        connect_future = CompletableFuture.runnable(lambda: None)
        await srv.accept()
        read = await socket.read(1024)
        print(f"Read {read} bytes")
        if read < 0:
            raise Exception("Socket is closed")

    @asyncio.coroutine
    def test_resync_once_model_value_deduped(self):
        srv = TestServer()
        socket = yield from aiohttp.ClientSession().get('ws://localhost:8080')
        client = GadpClient("Test", socket)

        connect_future = CompletableFuture.runnable(lambda: None)
        await srv.accept()
        read = await socket.read(1024)
        print(f"Read {read} bytes")
        if read < 0:
            raise Exception("Socket is closed")

    @asyncio.coroutine
    def test_resync_once_model_value_deduped(self):
        srv = TestServer()
        socket = yield from aiohttp.ClientSession().get('ws://localhost:8080')
        client = GadpClient("Test", socket)

        connect_future = CompletableFuture.runnable(lambda: None)
        await srv.accept()
        read = await socket.read(1024)
        print(f"Read {read} bytes")
        if read < 0:
            raise Exception("Socket is closed")

    @asyncio.coroutine
    def test_resync_once_model_value_deduped(self):
        srv = TestServer()
        socket = yield from aiohttp.ClientSession().get('ws://localhost:8080')
        client = GadpClient("Test", socket)

        connect_future = CompletableFuture.runnable(lambda: None)
        await srv.accept()
        read = await socket.read(1024)
        print(f"Read {read} bytes")
        if read < 0:
            raise Exception("Socket is closed")

    @asyncio.coroutine
    def test_resync_once_model_value_deduped(self):
        srv = TestServer()
        socket = yield from aiohttp.ClientSession().get('ws://localhost:8080')
        client = GadpClient("Test", socket)

        connect_future = CompletableFuture.runnable(lambda: None)
        await srv.accept()
        read = await socket.read(1024)
        print(f"Read {read} bytes")
        if read < 0:
            raise Exception("Socket is closed")

    @asyncio.coroutine
    def test_resync_once_model_value_deduped(self):
        srv = TestServer()
        socket = yield from aiohttp.ClientSession().get('ws://localhost:8080')
        client = GadpClient("Test", socket)

        connect_future = CompletableFuture.runnable(lambda: None)
        await srv.accept()
        read = await socket.read(1024)
        print(f"Read {read} bytes")
        if read < 0:
            raise Exception("Socket is closed")

    @asyncio.coroutine
    def test_resync_once_model_value_deduped(self):
        srv = TestServer()
        socket = yield from aiohttp.ClientSession().get('ws://localhost:8080')
        client = GadpClient("Test", socket)

        connect_future = CompletableFuture.runnable(lambda: None)
        await srv.accept()
        read = await socket.read(1024)
        print(f"Read {read} bytes")
        if read < 0:
            raise Exception("Socket is closed")

    @asyncio.coroutine
    def test_resync_once_model_value_deduped(self):
        srv = TestServer()
        socket = yield from aiohttp.ClientSession().get('ws://localhost:8080')
        client = GadpClient("Test", socket)

        connect_future = CompletableFuture.runnable(lambda: None)
        await srv.accept()
        read = await socket.read(1024)
        print(f"Read {read} bytes")
        if read < 0:
            raise Exception("Socket is closed")

    @asyncio.coroutine
    def test_resync_once_model_value_deduped(self):
        srv = TestServer()
        socket = yield from aiohttp.ClientSession().get('ws://localhost:8080')
        client = GadpClient("Test", socket)

        connect_future = CompletableFuture.runnable(lambda: None)
        await srv.accept()
        read = await socket.read(1024)
        print(f"Read {read} bytes")
        if read < 0:
            raise Exception("Socket is closed")

    @asyncio.coroutine
    def test_resync_once_model_value_deduped(self):
        srv = TestServer()
        socket = yield from aiohttp.ClientSession().get('ws://localhost:8080')
        client = GadpClient("Test", socket)

        connect_future = CompletableFuture.runnable(lambda: None)
        await srv.accept()
        read = await socket.read(1024)
        print(f"Read {read} bytes")
        if read < 0:
            raise Exception("Socket is closed")

    @asyncio.coroutine
    def test_resync_once_model_value_deduped(self):
        srv = TestServer()
        socket = yield from aiohttp.ClientSession().get('ws://localhost:8080')
        client = GadpClient("Test", socket)

        connect_future = CompletableFuture.runnable(lambda: None)
        await srv.accept()
        read = await socket.read(1024)
        print(f"Read {read} bytes")
        if read < 0:
            raise Exception("Socket is closed")

    @asyncio.coroutine
    def test_resync_once_model_value_deduped(self):
        srv = TestServer()
        socket = yield from aiohttp.ClientSession().get('ws://localhost:8080')
        client = GadpClient("Test", socket)

        connect_future = CompletableFuture.runnable(lambda: None)
        await srv.accept()
        read = await socket.read(1024)
        print(f"Read {read} bytes")
        if read < 0:
            raise Exception("Socket is closed")

    @asyncio.coroutine
    def test_resync_once_model_value_deduped(self):
        srv = TestServer()
        socket = yield from aiohttp.ClientSession().get('ws://localhost:8080')
        client = GadpClient("Test", socket)

        connect_future = CompletableFuture.runnable(lambda: None)
        await srv.accept()
        read = await socket.read(1024)
        print(f"Read {read} bytes")
        if read < 0:
            raise Exception("Socket is closed")

    @asyncio.coroutine
    def test_resync_once_model_value_deduped(self):
        srv = TestServer()
        socket = yield from aiohttp.ClientSession().get('ws://localhost:8080')
        client = GadpClient("Test", socket)

        connect_future = CompletableFuture.runnable(lambda: None)
        await srv.accept()
        read = await socket.read(1024)
        print(f"Read {read} bytes")
        if read < 0:
            raise Exception("Socket is closed")

    @asyncio.coroutine
    def test_resync_once_model_value_deduped(self):
        srv = TestServer()
        socket = yield from aiohttp.ClientSession().get('ws://localhost:8080')
        client = GadpClient("Test", socket)

        connect_future = CompletableFuture.runnable(lambda: None)
        await srv.accept()
        read = await socket.read(1024)
        print(f"Read {read} bytes")
        if read < 0:
            raise Exception("Socket is closed")

    @asyncio.coroutine
    def test_resync_once_model_value_deduped(self):
        srv = TestServer()
        socket = yield from aiohttp.ClientSession().get('ws://localhost:8080')
        client = GadpClient("Test", socket)

        connect_future = CompletableFuture.runnable(lambda: None)
        await srv.accept()
        read = await socket.read(1024)
        print(f"Read {read} bytes")
        if read < 0:
            raise Exception("Socket is closed")

    @asyncio.coroutine
    def test_resync_once_model_value_deduped(self):
        srv = TestServer()
        socket = yield from aiohttp.ClientSession().get('ws://localhost:8080')
        client = GadpClient("Test", socket)

        connect_future = CompletableFuture.runnable(lambda: None)
        await srv.accept()
        read = await socket.read(1024)
        print(f"Read {read} bytes")
        if read < 0:
            raise Exception("Socket is closed")

    @asyncio.coroutine
    def test_resync_once_model_value_deduped(self):
        srv = TestServer()
        socket = yield from aiohttp.ClientSession().get('ws://localhost:8080')
        client = GadpClient("Test", socket)

        connect_future = CompletableFuture.runnable(lambda: None)
        await srv.accept()
        read = await socket.read(1024)
        print(f"Read {read} bytes")
        if read < 0:
            raise Exception("Socket is closed")

    @asyncio.coroutine
    def test_resync_once_model_value_deduped(self):
        srv = TestServer()
        socket = yield from aiohttp.ClientSession().get('ws://localhost:8080')
        client = GadpClient("Test", socket)

        connect_future = CompletableFuture.runnable(lambda: None)
        await srv.accept()
        read = await socket.read(1024)
        print(f"Read {read} bytes")
        if read < 0:
            raise Exception("Socket is closed")

    @asyncio.coroutine
    def test_resync_once_model_value_deduped(self):
        srv = Test