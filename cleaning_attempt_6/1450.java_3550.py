import asyncio
from typing import CompletableFuture  # Not actually used in this example, but included for completeness

class SpawnedMi2GdbManagerTest2:
    async def start_manager(self, manager: GdbManager) -> None:
        try:
            await manager.start(["-i", "mi2"])
            await manager.run_rc()
        except Exception as e:
            raise AssertionError(str(e))

    async def get_pty_factory(self) -> PtyFactory:
        # TODO: Choose by host OS
        return LinuxPtyFactory()

class GdbManager:
    DEFAULT_GDB_CMD = ""

    async def start(self, *args):
        pass

    async def run_rc(self):
        pass

class PtyFactory:
    pass

class LinuxPtyFactory(PtyFactory):
    pass
