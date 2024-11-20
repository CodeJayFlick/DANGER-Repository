import asyncio

class MemoryWriter:
    async def write_memory(self, address: int, data: bytes) -> asyncio.Future[None]:
        # TODO: Use bytearray instead?
        pass  # Implement your logic here


# Example usage:
async def main():
    memory_writer = MemoryWriter()
    await memory_writer.write_memory(0x12345678, b'Hello, World!')

if __name__ == "__main__":
    asyncio.run(main())
