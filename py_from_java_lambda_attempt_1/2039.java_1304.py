Here is the translation of the Java code into Python:

```Python
class JdiModelTargetBreakpointContainer:
    def __init__(self, vm):
        self.vm = vm
        self.specs_by_info = weakref.WeakValueDictionary()

    SUPPORTED_KINDS = {k for k in TargetBreakpointKind}

    def breakpoint_created(self, info, cause):
        self.change_elements([], [self.get_target_breakpoint_spec(info)], {}, "Created")

    def breakpoint_modified(self, new_info, old_info, cause):
        self.get_target_breakpoint_spec(old_info).update_info(old_info, new_info, "Modified")

    def breakpoint_deleted(self, info, cause):
        with self.lock:
            del self.specs_by_info[info]
        self.change_elements([str(info)], [], {}, "Deleted")

    async def place_breakpoint(self, range: AddressRange, kinds: set) -> CompletableFuture:
        if TargetBreakpointKind.SW_EXECUTE in kinds:
            location = await self.vm.impl.get_location(range.min_address)
            target_location = JdiModelTargetLocation(location, True)
            info = await target_location.add_breakpoint()
            breakpoint_created(info, JdiCause.Causes.UNCLAIMED)

    async def place_breakpoint(self, expression: str, kinds: set) -> CompletableFuture:
        if TargetBreakpointKind.SW_EXECUTE in kinds and isinstance(target_object := self.get_target_object(expression), JdiModelTargetLocation):
            target_location = target_object
            info = await target_location.add_breakpoint()
            breakpoint_created(info, JdiCause.Causes.UNCLAIMED)
        elif (kinds & {TargetBreakpointKind.READ, TargetBreakpointKind.HW_EXECUTE}) and isinstance(target_object := self.get_target_object(expression), JdiModelTargetField) and self.vm.can_watch_field_access():
            target_field = target_object
            info = await target_field.add_access_watchpoint()
            breakpoint_created(info, JdiCause.Causes.UNCLAIMED)
        elif TargetBreakpointKind.WRITE in kinds and isinstance(target_object := self.get_target_object(expression), JdiModelTargetField) and self.vm.can_watch_field_modification():
            target_field = target_object
            info = await target_field.add_modification_watchpoint()
            breakpoint_created(info, JdiCause.Causes.UNCLAIMED)

    def get_target_breakpoint_spec(self, info):
        return self.specs_by_info.get(info, lambda i: JdiModelTargetBreakpointSpec(self, info, True))

    async def update_using_breakpoints(self, by_number: dict) -> CompletableFuture:
        specs = list(by_number.values().map(lambda x: self.get_target_breakpoint_spec(x)).collect(Collectors.toList()))
        await set_elements(specs, {}, "Refreshed")

    async def request_elements(self, refresh):
        return CompletableFuture.completed_future(None)
```

Please note that this is a direct translation of the Java code into Python.