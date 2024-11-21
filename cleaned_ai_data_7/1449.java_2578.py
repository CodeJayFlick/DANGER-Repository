import asyncio
from unittest import skip  # For @skip decorator in Python


class SpawnedMi2Gdb7Dot6Dot1ManagerTest:
    async def start_manager(self, manager):
        try:
            await manager.start(["/opt/gdb-7.6.1/bin/gdb", "-i", "mi2"])
            return await manager.run_rc()
        except Exception as e:
            raise AssertionError(str(e))

    @skip("Need to install GDB 7.6.1 to the expected directory on CI")
    def get_pty_factory(self):
        # TODO: Choose by host OS
        from ptyprocess import LinuxPtyFactory
        return LinuxPtyFactory()
