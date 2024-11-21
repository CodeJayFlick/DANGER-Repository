import asyncio
from typing import List, Dict, Any

class AbstractGdbManagerTest:
    TIMEOUT_MILLISECONDS = 5000 if SystemUtilities.is_in_testing_batch_mode() else float('inf')

    def __init__(self):
        self.pty_factory: Any = None

    async def start_manager(self, manager) -> asyncio.Future:
        # No equivalent in Python
        pass

    def stop_manager(self) -> None:
        # Nothing by default
        pass

    @staticmethod
    def wait_on(future: asyncio.Future) -> Any:
        try:
            return await future
        except ExecutionError as e:
            raise e.cause from None

    async def test_add_inferior(self, manager):
        with GdbManager(manager.pty_factory()) as mgr:
            await self.wait_on(mgr.start_manager())
            inferior = await self.wait_on(mgr.add_inferior())
            assert inferior.id == 2
            assert set([1, 2]) == set(mgr.get_known_inferiors().keys())

    async def test_remove_inferior(self, manager):
        with GdbManager(manager.pty_factory()) as mgr:
            await self.wait_on(mgr.start_manager())
            inf = await self.wait_on(mgr.add_inferior())
            assert 2 == len(mgr.get_known_inferiors())
            await self.wait_on(inf.remove())
            assert 1 == len(mgr.get_known_inferiors())

    async def test_remove_current_inferior(self, manager):
        with GdbManager(manager.pty_factory()) as mgr:
            await self.wait_on(mgr.start_manager())
            sel_evt_ids = AsyncReference(list(), None)
            mgr.add_events_listener(GdbEventsListenerAdapter(sel_evt_ids))
            await self.wait_on(mgr.list_available_processes())

    async def test_console_capture(self, manager):
        with GdbManager(manager.pty_factory()) as mgr:
            await self.wait_on(mgr.start_manager())
            out = await self.wait_on(mgr.console_capture("echo test"))
            assert "test" == out.strip()

    # ... and so on for the rest of the tests
