class DbgModelTargetBreakpointContainer:
    def __init__(self):
        self.supported_kinds = set(TargetBreakpointKind)

    def breakpoint_created(self, info: 'DbgBreakpointInfo', cause: 'DbgCause'):
        # TODO: Seems terrible to duplicate this static attribute on each instance
        pass

    def breakpoint_modified(self, new_info: 'DbgBreakpointInfo', old_info: 'DbgBreakpointInfo', 
                             cause: 'DbgCause'):
        pass

    def breakpoint_deleted(self, info: 'DbgBreakpointInfo', cause: 'DbgCause'):
        # TODO: Implement delete logic
        pass

    def breakpoint_hit(self, info: 'DbgBreakpointInfo', cause: 'DbgCause'):
        target_thread = self.get_target_thread()
        spec = self.get_target_breakpoint_spec(info)
        listeners.fire.breakpoint_hit(None, target_thread, None, spec, spec)
        spec.breakpoint_hit()

    def get_target_breakpoint_spec(self, info):
        model_object = self.model.get_model_object(info.debug_breakpoint)
        if model_object is not None:
            return model_object
        else:
            return DbgModelTargetBreakpointSpec(self, info)

    async def request_elements(self, refresh: bool) -> 'CompletableFuture[Void]':
        manager = self.manager
        result = await manager.list_breakpoints()
        specs = [self.get_target_breakpoint_spec(by_number) for by_number in result.values()]
        self.set_elements(specs, {}, "Refreshed")
