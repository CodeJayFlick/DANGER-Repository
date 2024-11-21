import asyncio

class DbgModelTargetMemoryContainer:
    def get_target_memory(self, region):
        # Implement this method in your subclass
        pass

    async def read_memory(self, address: int, length: int) -> bytes:
        # Implement this method in your subclass
        pass

    async def write_memory(self, address: int, data: bytes) -> None:
        # Implement this method in your subclass
        pass

    async def request_elements(self, refresh: bool) -> None:
        # Implement this method in your subclass
        pass
