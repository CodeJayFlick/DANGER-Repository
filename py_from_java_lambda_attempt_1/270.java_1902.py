Here is the translation of the Java interface `ManagedBreakpointRecorder` into a Python class:

```python
class ManagedBreakpointRecorder:
    def offer_breakpoint_container(self, added):
        pass  # implement this method in your subclass

    def offer_breakpoint_location(self, target: 'TargetObject', added: 'TargetBreakpointLocation'):
        pass  # implement this method in your subclass

    def record_breakpoint(self, loc: 'TargetBreakpointLocation', trace_threads: set['TraceThread']):
        pass  # implement this method in your subclass

    def remove_breakpoint_location(self, removed: 'TargetBreakpointLocation'):
        pass  # implement this method in your subclass

    @property
    def breakpoint_container(self) -> 'TargetBreakpointSpecContainer':
        raise NotImplementedError("Must be implemented by a subclass")

    def get_trace_breakpoint(self, bpt: 'TargetBreakpointLocation') -> 'TraceBreakpoint':
        raise NotImplementedError("Must be implemented by a subclass")

    def breakpoint_location_changed(self, length: int, trace_addr: 'Address', path: str):
        pass  # implement this method in your subclass

    def breakpoint_spec_changed(self, spec: 'TargetBreakpointSpec', enabled: bool, kinds: set['TraceBreakpointKind']):
        pass  # implement this method in your subclass
```

Note that I've used type hints for the methods and variables to indicate their expected types. This is not strictly necessary for Python code, but it can be helpful for documentation purposes.

Also note that some of these methods are marked as `pass`, which means they do nothing when called. In a real implementation, you would need to replace these with actual method implementations.