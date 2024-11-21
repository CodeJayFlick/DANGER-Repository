import weakref

class GdbModelTargetAvailableContainer:
    NAME = "Available"

    def __init__(self, session):
        self.impl = session.impl
        self.attachables_by_id = weakref.WeakValueDictionary()
        super().__init__(session.impl, session, NAME, "AvailableContainer")

    def request_elements(self, refresh=False):
        return self.impl.gdb.list_available_processes().then_accept(lambda list: 
            available = [self.get_target_attachable(process) for process in list]
            self.set_elements(available, "Refreshed")
        )

    def get_target_attachable(self, process):
        pid = process.pid
        if pid not in self.attachables_by_id:
            self.attachables_by_id[pid] = GdbModelTargetAttachable(self.impl, self, process)
        return self.attachables_by_id[pid]

    async def write_configuration_option(self, key, value):
        if key == "Base":
            if isinstance(value, int):
                await self.change_attributes([key], {key: value}, "Modified")
                for child in self.get_cached_elements().values():
                    child.set_base(value)
            else:
                raise DebuggerIllegalArgumentException("Base should be numeric")

    async def change_attributes(self, keys, attributes, message=""):
        # implement this method
        pass

class GdbModelTargetAttachable:
    def __init__(self, impl, container, process):
        self.impl = impl
        self.container = weakref.ref(container)
        self.process = process

    @property
    def base(self):
        return self.process.base

    async def set_base(self, value):
        # implement this method
        pass

class GdbProcessThreadGroup:
    def __init__(self):
        pass

    @property
    def pid(self):
        raise NotImplementedError("pid is not implemented")

# This class represents the equivalent of a CompletableFuture in Java.
from asyncio import Future as CompletableFuture, create_task

def then_accept(self, func):
    future = CompletableFuture()
    task = create_task(func())
    task.add_done_callback(lambda f: future.set_result(f.result()))
    return future
