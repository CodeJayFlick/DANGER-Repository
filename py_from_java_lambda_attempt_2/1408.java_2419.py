Here is a translation of the Java code into equivalent Python code:

```Python
import asyncio
from typing import List, Dict, Any

class GdbModelTargetProcessMemory:
    def __init__(self, inferior: 'GdbInferior') -> None:
        self.impl = inferior.impl
        self.inferior = inferior
        self.regions_by_start = WeakValueHashMap()

    async def update_using_mappings(self, by_start: Dict[BigInteger, GdbMemoryMapping]) -> None:
        regions = []
        with self.lock:
            for mapping in by_start.values():
                region = await self.get_target_region(mapping)
                if region is not None and region.is_same(mapping):
                    continue
                region = GdbModelTargetMemoryRegion(self, mapping)
                self.regions_by_start[mapping.start] = region
                regions.append(region)

        set_elements(regions, "Refreshed")

    async def request_elements(self, refresh: bool) -> asyncio.Future:
        return await self.do_refresh()

    async def do_refresh(self) -> asyncio.Future:
        if self.inferior.get_pid() is None:
            await set_elements([], "Refreshed (while no process)")
            return asyncio.shield(asyncio.NIL)

        try:
            mappings = await self.inferior.list_mappings()
        except Exception as e:
            Msg.error(self, f"Could not list regions. Using default.")
            return {}

        await update_using_mappings(mappings)

    async def get_target_region(self, mapping: GdbMemoryMapping) -> 'GdbModelTargetMemoryRegion':
        region = self.regions_by_start.get(mapping.start)
        if region is not None and region.is_same(mapping):
            return region
        region = GdbModelTargetMemoryRegion(self, mapping)
        self.regions_by_start[mapping.start] = region
        return region

    async def do_read_memory(self, address: Address, offset: int, length: int) -> asyncio.Future:
        buf = bytearray(length)
        range_ = await new_address_range(address, length)

        try:
            data = await self.inferior.read_memory(offset, buf)
        except Exception as e:
            raise DebuggerMemoryAccessException(f"Cannot read at {address}")

        if not (0 <= offset < len(data)):
            raise DebuggerMemoryAccessException("Invalid memory access")

        return asyncio.shield(asyncio.to_thread(set_content, data))

    async def read_memory(self, address: Address, length: int) -> asyncio.Future:
        return await self.impl.gate_future(await self.do_read_memory(address, 0, length))

    async def write_memory(self, address: Address, data: bytearray) -> asyncio.Future:
        future = await self.inferior.write_memory(0, buf)
        return await self.impl.gate_future(future.then_set(lambda __: Msg.fire("memoryUpdated", self, address, data)))

    def invalidate_memory_caches(self) -> None:
        listeners.fire_invalidate_cache_requested(self)

    async def memory_changed(self, offset: int, length: int) -> asyncio.Future:
        await do_read_memory(0, 0, length).exceptionally(lambda e: Msg.error(self, f"Failed to update memory contents on memory-changed event", e))

    async def state_changed(self, sco: GdbStateChangeRecord) -> asyncio.Future:
        return (await self.do_refresh()).then_set(lambda __: AsyncFence().include({region.state_changed(sco) for region in self.regions_by_start.values()})).then_set(lambda __: AsyncFence().ready())

    async def refresh_internal(self) -> asyncio.Future:
        try:
            await do_refresh()
        except Exception as e:
            self.impl.report_error(self, "Problem refreshing inferior's memory regions", e)
```

Please note that Python does not support Java-like constructs such as `@Override`, and it also doesn't have direct equivalent of Java's exception handling.