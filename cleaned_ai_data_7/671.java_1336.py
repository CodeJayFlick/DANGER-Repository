import asyncio

class DbgMemoryOperations:
    async def read_memory(self, addr: int, buf: bytearray, len: int) -> dict:
        # TO DO: implement your logic here to read memory and return ranges successfully read
        pass

    async def read_memory(self, addr: int, buf: bytearray) -> dict:
        return await self.read_memory(addr, buf, len(buf))

    async def write_memory(self, addr: int, buf: bytearray, len: int) -> asyncio.Future:
        # TO DO: implement your logic here to write memory and return a future that completes when the write succeeds
        pass

    async def write_memory(self, addr: int, buf: bytearray) -> asyncio.Future:
        return await self.write_memory(addr, buf, len(buf))
