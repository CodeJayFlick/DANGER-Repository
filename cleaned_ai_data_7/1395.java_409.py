from concurrent.futures import Future

class GdbModelSelectableObject:
    def __init__(self):
        pass

    async def set_active(self) -> Future[None]:
        return await Future(None)
