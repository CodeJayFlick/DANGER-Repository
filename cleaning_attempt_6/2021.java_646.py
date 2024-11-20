import asyncio

class JdiModelTargetAttacher:
    def __init__(self):
        pass

    async def attach(self, attachable: 'TargetAttachable') -> asyncio.Future:
        # implement your logic here
        return await asyncio.create_future()

    async def attach(self, pid: int) -> asyncio.Future:
        # implement your logic here
        return await asyncio.create_future()
