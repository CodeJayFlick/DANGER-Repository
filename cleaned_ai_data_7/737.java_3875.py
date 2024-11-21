import asyncio
from abc import ABC, abstractmethod


class DbgModelTargetAttacher(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def attach(self, target_attachable: 'DbgProcess') -> None:
        raise NotImplementedError("Method not implemented")

    @abstractmethod
    async def attach(self, pid: int) -> None:
        raise NotImplementedError("Method not implemented")


class DbgModelTargetAvailable:
    pass


class DbgProcess:
    def __init__(self):
        pass

    async def attach(self, pid: int) -> None:
        # TODO: implement this method
        return None


async def main():
    attacher = DbgModelTargetAttacher()
    process = DbgProcess()

    await attacher.attach(process)
    await attcher.attach(12345)


if __name__ == "__main__":
    asyncio.run(main())
