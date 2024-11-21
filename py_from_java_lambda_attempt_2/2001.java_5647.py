Here is the translation of the given Java code into Python:

```Python
import asyncio
from typing import Any, Dict, List

class AsyncFakeByteChannel:
    def __init__(self):
        self.read_reqs = []
        self.write_reqs = []

    async def read(self, dst: bytes, attachment: Any) -> int:
        awaitable = ReadReq(dst=dst, attachment=attachment)
        self.read_reqs.append(awaitable)
        return 0

    async def write(self, src: bytes, attachment: Any) -> int:
        awaitable = WriteReq(src=src, attachment=attachment)
        self.write_reqs.append(awaitable)
        return 1


class ReadReq:
    def __init__(self, dst: bytes, attachment: Any):
        self.dst = dst
        self.attachment = attachment

    async def complete(self, src: bytes) -> None:
        await asyncio.to_thread(lambda: self.dst.put(src))
        print(f"Completed read with {src}")

    async def error(self, exc: Exception) -> None:
        raise exc


class WriteReq:
    def __init__(self, src: bytes, attachment: Any):
        self.src = bytearray(src)
        self.attachment = attachment

    async def complete(self, dst: bytes) -> None:
        await asyncio.to_thread(lambda: self.src.extend(dst))
        print(f"Completed write with {dst}")

    async def error(self, exc: Exception) -> None:
        raise exc


async def test_send_buffer_grows() -> None:
    channel = AsyncProtobufMessageChannel(AsyncFakeByteChannel(), 1)
    await channel.write(Gadp.RootMessage.newBuilder().setSequence(0x12345678).build())
    write_req = ReadReq(dst=bytearray(), attachment=None)
    data = bytearray(write_req.src.remaining()).fromhex("0000000608f8acd19101")
    write_req.complete(data)
    print(f"Completed send with {data}")


async def test_recv_buffer_grows() -> None:
    channel = AsyncProtobufMessageChannel(AsyncFakeByteChannel(), 1)

    data = bytearray.fromhex(
        "0000000608f8acd19101000000608f8acd19101"
    )
    awaitable = channel.read(Gadp.RootMessage.parse_from)
    read_req = ReadReq(dst=bytearray(1), attachment=None)
    await read_req.complete(data[:1])
    print(f"Completed receive with {data[:1]}")

    read_req = ReadReq(dst=bytearray(), attachment=None)
    await read_req.complete(data[1:2].decode("utf-8"))
    print(f"Completed receive with {data[1:2].decode('utf-8')}")
```

Please note that Python does not support direct translation of Java code. The above Python code is a rewritten version of the given Java code, and it may behave differently than the original Java code due to differences in language features and libraries used.