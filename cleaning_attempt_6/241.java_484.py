class EnableBreakpointActionItem:
    def __init__(self, togglable):
        self.togglable = togglable

    def equals(self, obj):
        if not isinstance(obj, EnableBreakpointActionItem):
            return False
        that = obj
        if self.togglable != that.togglable:
            return False
        return True

    def __hash__(self):
        return hash((type(self), self.togglable))

    async def execute(self):
        await self.togglable.enable()
