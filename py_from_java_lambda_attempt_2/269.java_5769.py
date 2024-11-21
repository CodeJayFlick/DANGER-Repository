Here is the translation of the Java interface `AbstractTraceRecorder` to a Python class:

```python
class AbstractTraceRecorder:
    def __init__(self):
        pass

    def get_trace(self) -> object:
        """Get the trace"""
        return None  # Replace with actual implementation

    def get_snap(self) -> int:
        """Get the snap value"""
        return -1  # Replace with actual implementation

    def get_memory_mapper(self) -> object:
        """Get the memory mapper"""
        return None  # Replace with actual implementation

    def get_breakpoint_recorder(self) -> object:
        """Get the breakpoint recorder"""
        return None  # Replace with actual implementation
```

Note that I've used Python's built-in `object` type to represent the Java types, as there is no direct equivalent in Python. You'll need to replace these placeholders with your own implementations or imports from other modules.