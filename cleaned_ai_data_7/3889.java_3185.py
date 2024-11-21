class StackDepthChangeEvent:
    REMOVE_STACK_DEPTH_CHANGE = 0
    UPDATE_STACK_DEPTH_CHANGE = 1

    def __init__(self, source, id, command, stack_depth_change):
        self.stack_depth_change = stack_depth_change

    @property
    def stack_depth_change(self):
        return self._stack_depth_change

    def __str__(self):
        return f"StackDepthChangeEvent(id={self.id}, command='{self.command}', stack_depth_change={self.stack_depth_change})"
