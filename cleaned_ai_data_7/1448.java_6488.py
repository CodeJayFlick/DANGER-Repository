import asyncio
from unittest import skip  # For @skip decorator


class SpawnedCliGdbManagerTest:
    async def start_manager(self, manager):
        try:
            await manager.start()
            return await manager.run_rc()
        except Exception as e:
            raise AssertionError(e)

    def get_pty_factory(self):  # TODO: Choose by host OS
        return LinuxPtyFactory()  # Assuming a class named LinuxPtyFactory exists


# Note that Python does not have direct equivalent of Java's CompletableFuture.
# The above code uses asyncio library to achieve similar functionality.

