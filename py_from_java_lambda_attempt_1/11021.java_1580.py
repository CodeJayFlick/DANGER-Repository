Here is the translation of the Java code to Python:
```
class ToolState:
    def __init__(self, tool: 'PluginTool', domain_object):
        self.tool = tool
        self.before_state = tool.get_undo_redo_tool_state(domain_object)
        self.after_state = None  # Initialize after state as None

    def restore_after_undo(self, domain_object):
        if self.before_state is not None:
            self.before_state.restore_tool(domain_object)

    def restore_after_redo(self, domain_object):
        if self.after_state is not None:
            self.after_state.restore_tool(domain_object)
        else:
            raise ValueError("After state has not been set")

    def get_after_state(self, domain_object):
        self.after_state = self.tool.get_undo_redo_tool_state(domain_object)

class PluginTool:  # Assuming this class exists in Python
    pass

class DomainObject:  # Assuming this class exists in Python
    pass

class UndoRedoToolState:
    def __init__(self, tool: 'PluginTool', domain_object):
        self.tool = tool
        self.domain_object = domain_object

    def restore_tool(self, domain_object):
        raise NotImplementedError("Subclasses must implement restore_tool")
```
Note that I've used type hints for the method parameters and return types to indicate their expected types. This is not strictly necessary in Python 3.x, but it can help with code readability and catch potential errors at runtime.

Also, I've assumed that `PluginTool`, `DomainObject`, and `UndoRedoToolState` are classes that exist elsewhere in the codebase or will be implemented by subclasses of these classes. If you need to implement these classes as well, please let me know!