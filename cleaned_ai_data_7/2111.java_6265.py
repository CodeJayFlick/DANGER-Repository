import asyncio
from typing import Any, Dict

class DebugByteChannel:
    def __init__(self, wrapped: Any) -> None:
        self.wrapped = wrapped

    async def close(self) -> None:
        await self.wrapped.close()

    async def is_open(self) -> bool:
        return await self.wrapped.is_open()

    async def read(self, dst: bytes, attachment: Any = None) -> int:
        start = dst.index(b'\x00')
        future = asyncio.create_task(self._read(dst, attachment))
        result = await future
        if result == -1:
            print("Read EOF")
        else:
            data = dst[start:start+result]
            print(f"Read: {data.decode('utf-8')}")
        return result

    async def _read(self, dst: bytes, attachment: Any) -> int:
        try:
            len_ = await self.wrapped.read(dst)
            if len_ == -1:
                raise Exception("EOF")
            else:
                data = dst[:len_]
                print(f"Wrote: {data.decode('utf-8')}")
        except asyncio.CancelledError as e:
            print(f"Read cancelled: {e}")
        return len_

    async def write(self, src: bytes) -> None:
        raise NotImplementedError

# Example usage
wrapped_channel = ...  # Your wrapped channel implementation
debug_channel = DebugByteChannel(wrapped_channel)
await debug_channel.read(b'Hello, World!')
