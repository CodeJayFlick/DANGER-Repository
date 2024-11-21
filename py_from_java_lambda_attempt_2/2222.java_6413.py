Here is the translation of the Java code into Python:

```Python
import asyncio
from typing import List, Set, Dict, Any

class DebuggerCallbackReorderer:
    def __init__(self, listener):
        self.listener = listener
        self.records: Dict[Any, 'ObjectRecord'] = {}
        self.last_event = asyncio.Future()

    class ObjectRecord:
        def __init__(self, obj):
            self.obj = obj
            self.added_to_parent = asyncio.create_future()
            self.complete = None

        async def completed(self) -> Any:
            records = self.records  # type: Dict[Any, 'ObjectRecord']
            del records[self.obj]
            attributes = self.obj.get_callback_attributes() or {}
            if attributes:
                await listener.attributes_changed(self.obj, [], dict(attributes))
            elements = self.obj.get_callback_elements() or {}
            if elements:
                await listener.elements_changed(self.obj, [], dict(elements))

        async def added(self):
            pass

        async def removed(self):
            if not self.added_to_parent.done():
                self.added_to_parent.cancel()

    def defensive(self, r: Any, cb: str) -> None:
        try:
            r()
        except Exception as e:
            Msg.error(self, f"Listener {self.listener} caused exception processing {cb}", e)

    async def catastrophic(self, t: Exception):
        if self.disposed:
            return
        await listener.catastrophic(t)

    async def model_closed(self, reason: Any):
        if self.disposed:
            return
        await listener.model_closed(reason)

    async def model_opened(self) -> None:
        pass

    async def created(self, obj: Any) -> None:
        records = self.records  # type: Dict[Any, 'ObjectRecord']
        record = ObjectRecord(obj)
        records[obj] = record
        await defensive(lambda: listener.created(obj), "created")

    async def invalidated(self, object: Any, branch: Any, reason: str):
        if self.disposed:
            return
        remove = records.get(object)  # type: 'ObjectRecord'
        if remove is not None:
            await remove.removed()
        await defensive(lambda: listener.invalidated(object, branch, reason), "invalidated")

    async def root_added(self, obj: Any):
        if self.disposed:
            return
        await defensive(lambda: listener.root_added(obj), "rootAdded")
        record = records.get(obj)  # type: 'ObjectRecord'
        if record is not None:
            await record.added()

    async def attributes_changed(self, object: Any, removed: List[str], added: Dict[str, Any]):
        if self.disposed:
            return
        for ent in added.items():
            obj = ent[1]
            if isinstance(obj, Object):
                record = records.get(obj)  # type: 'ObjectRecord'
                if record is not None:
                    await record.added()

    async def elements_changed(self, object: Any, removed: List[str], added: Dict[str, Any]):
        if self.disposed:
            return
        for ent in added.items():
            obj = ent[1]
            if isinstance(obj, Object):
                record = records.get(obj)  # type: 'ObjectRecord'
                if record is not None:
                    await record.added()

    async def ordered_on_objects(self, objects: List[Any], r: Any, cb: str) -> None:
        fence = asyncio.create_future()
        fence.set_result(None)
        for obj in objects:
            record = records.get(obj)  # type: 'ObjectRecord'
            if record is not None:
                await defensive(lambda: listener.event(obj), "event")
        last_event = fence

    async def breakpoint_hit(self, container: Any, trapped: Any, frame: Any, spec: Any, breakpoint: Any):
        if self.disposed:
            return
        args = [container, trapped, frame, spec, breakpoint]
        await ordered_on_objects(args, lambda: listener.breakpoint_hit(*args), "breakpointHit")

    async def console_output(self, console: Any, channel: Any, data: bytes) -> None:
        if self.disposed:
            return
        args = [console]
        await ordered_on_objects(args, lambda: listener.console_output(*args), "consoleOutput")

    def gather_objects(self, *collections):
        objs = set()
        for col in collections:
            for val in col:
                if isinstance(val, Object):
                    objs.add(val)
        return list(objs)

    async def event(self, object: Any, thread: Any, type: str, description: str, parameters: List[Any]):
        if self.disposed:
            return
        args = [object]
        if thread is not None:
            args.append(thread)
        await ordered_on_objects(gather_objects(*args), lambda: listener.event(*args), f"event({type}) {description}")

    async def invalidate_cache_requested(self, object: Any):
        if self.disposed:
            return
        args = [object]
        await ordered_on_objects(args, lambda: listener.invalidate_cache_requested(object), "invalidateCacheRequested")

    async def memory_read_error(self, memory: Any, range: Any, e: Exception) -> None:
        if self.disposed:
            return
        args = [memory]
        await ordered_on_objects(args, lambda: listener.memory_read_error(*args, e), "memoryReadError")

    async def memory_updated(self, memory: Any, address: Any, data: bytes):
        if self.disposed:
            return
        args = [memory]
        await ordered_on_objects(args, lambda: listener.memory_updated(*args), "memoryUpdated")

    async def registers_updated(self, bank: Any, updates: Dict[str, bytes]):
        if self.disposed:
            return
        args = [bank]
        await ordered_on_objects(args, lambda: listener.registers_updated(*args), "registersUpdated")

    def dispose(self) -> None:
        self.disposed = True
        for rec in list(self.records.values()):
            rec.cancel()
        self.records.clear()

if __name__ == "__main__":
    pass