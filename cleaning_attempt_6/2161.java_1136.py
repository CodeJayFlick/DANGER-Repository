import asyncio

class MemoryReader:
    async def read_memory(self, address: int, length: int) -> bytes:
        # TODO: Use bytearray instead?
        return await self._wrapped_read(address, length)

    async def _wrapped_read(self, address: int, length: int) -> bytes:
        pass  # Implement the wrapped read method
