class BreakpointActionSet(set):
    def plan_enable(self, loc: 'TargetBreakpointLocation') -> 'EnableBreakpointActionItem':
        if isinstance(loc, TargetTogglable):
            action = EnableBreakpointActionItem(loc)
            self.add(action)
            return action
        spec = loc.get_specification()
        if isinstance(spec, TargetTogglable):
            action = EnableBreakpointActionItem(spec)
            self.add(action)
            return action
        return None

    def plan_disable(self, loc: 'TargetBreakpointLocation') -> 'DisableBreakpointActionItem':
        if isinstance(loc, TargetTogglable):
            action = DisableBreakpointActionItem(loc)
            self.add(action)
            return action
        spec = loc.get_specification()
        if isinstance(spec, TargetTogglable):
            action = DisableBreakpointActionItem(spec)
            self.add(action)
            return action
        return None

    def plan_delete(self, loc: 'TargetBreakpointLocation') -> 'DeleteBreakpointActionItem':
        if isinstance(loc, TargetDeletable):
            action = DeleteBreakpointActionItem(loc)
            self.add(action)
            return action
        spec = loc.get_specification()
        if isinstance(spec, TargetTogglable):
            action = DeleteBreakpointActionItem(spec)
            self.add(action)
            return action
        return None

    def execute(self) -> 'CompletableFuture[None]':
        fence = AsyncFence()
        for item in self:
            fence.include(item.execute())
        return fence.ready()

class EnableBreakpointActionItem:
    def __init__(self, loc: TargetTogglable):
        pass  # implement me

class DisableBreakpointActionItem:
    def __init__(self, loc: TargetTogglable):
        pass  # implement me

class DeleteBreakpointActionItem:
    def __init__(self, loc: TargetDeletable):
        pass  # implement me
