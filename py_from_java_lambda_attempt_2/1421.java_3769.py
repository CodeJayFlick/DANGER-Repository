Here is a translation of the Java code into equivalent Python:

```Python
class GdbModelTargetThreadContainer:
    def __init__(self):
        self.impl = None  # Assuming this will be set later
        self.inferior = None  # Assuming these will also be set later

    @property
    def name(self):
        return "Threads"

    def thread_created(self, thread: 'GdbThread') -> 'GdbModelTargetThread':
        target_thread = self.get_target_thread(thread)
        self.change_elements([target_thread], ["Created"])
        return target_thread

    def thread_exited(self, thread_id: int) -> None:
        if not hasattr(self, "cached_elements"):
            self.cached_elements = {}
        
        target_thread = self.cached_elements.get(GdbModelTargetThread.index_thread(thread_id))
        if target_thread is None:
            print(f"Thread {thread_id} exited, but was not in model.")
        else:
            self.impl.delete_model_object(target_thread.thread)
        
        self.change_elements([GdbModelTargetThread.index_thread(thread_id)], [], "Exited")

    def update_using_threads(self, by_tid: dict) -> None:
        if not hasattr(self, "cached_elements"):
            self.cached_elements = {}
        
        threads = list(by_tid.values())
        for thread in threads:
            target_thread = self.get_target_thread(thread)
            self.change_elements([target_thread], [], "Refreshed")
        
        removed_threads = [thread for thread in self.cached_elements if GdbModelTargetThread.index_thread(int(thread.thread_id)) not in by_tid]
        for target_thread in removed_threads:
            self.impl.delete_model_object(target_thread.thread)

    def request_elements(self, refresh: bool) -> CompletableFuture:
        if not refresh:
            self.update_using_threads(self.inferior.get_known_threads())
            return AsyncUtils.NIL
        else:
            return self.do_refresh()

    async def do_refresh(self):
        threads = await self.inferior.list_threads()
        self.update_using_threads(threads)

    def get_target_thread(self, thread: 'GdbThread') -> 'GdbModelTargetThread':
        if not hasattr(self, "cached_elements"):
            self.cached_elements = {}
        
        model_object = self.impl.get_model_object(thread)
        if model_object is None:
            return GdbModelTargetThread(self, parent=thread.inferior, thread=thread)
        else:
            return model_object

    def get_target_thread_if_present(self, thread: 'GdbThread') -> Optional['GdbModelTargetThread']:
        return self.impl.get_model_object(thread)

    async def invalidate_register_caches(self) -> None:
        for thread in self.inferior.get_known_threads().values():
            target_thread = await self.get_target_thread(thread)
            if target_thread is not None:
                await target_thread.invalidate_register_caches()

    async def state_changed(self, sco: 'GdbStateChangeRecord') -> CompletableFuture:
        if sco.state != GdbState.STOPPED:
            return await self.update_thread_states(sco)
        
        return (await self.request_elements(False)).thenCompose(lambda __: 
            self.update_thread_states(sco).exceptionally(__ => 
                print(f"Could not update threads {self} on STOPPED")
            )
        )

    async def update_thread_states(self, sco: 'GdbStateChangeRecord') -> CompletableFuture:
        fence = AsyncFence()
        
        for thread in self.inferior.get_known_threads().values():
            target_thread = await self.get_target_thread(thread)
            if target_thread is not None:
                fence.include(await target_thread.state_changed(sco))
        
        return fence.ready()

    def breakpoint_hit(self, reason: 'GdbBreakpointHitReason') -> 'GdbModelTargetBreakpointLocation':
        thread = self.impl.gdb.get_thread(reason.thread_id)
        return await self.get_target_thread(thread).breakpoint_hit(reason)

    async def write_configuration_option(self, key: str, value) -> CompletableFuture:
        if key == GdbStateChangeRecord.BASE_ATTRIBUTE_NAME and isinstance(value, int):
            for child in self.cached_elements.values():
                child.set_base(value)
            
            await self.change_attributes([GdbModelTargetThread.index_thread(thread_id)], {key: value}, "Modified")
        
        return AsyncUtils.NIL

    async def refresh_internal(self) -> CompletableFuture:
        try:
            await self.do_refresh()
        except Exception as ex:
            print(f"Problem refreshing inferior's threads. Error: {ex}")
```

Please note that this is a translation of the Java code into equivalent Python, and it may not be exactly what you would write in Python if you were starting from scratch.