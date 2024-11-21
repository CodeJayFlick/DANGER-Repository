Here is the translation of the Java interface into a Python class:

```Python
class DebuggerMemoryMapper:
    def trace_to_target(self, trace_addr):
        """Map the given address from the trace into the target process"""
        pass  # Implement this method in your subclass

    def trace_to_target_range(self, trace_range):
        """Map the given address range from the trace into the target process"""
        pass  # Implement this method in your subclass

    def target_to_trace(self, target_addr):
        """Map the given address from the target process into the trace"""
        pass  # Implement this method in your subclass

    def target_to_trace_range(self, target_range):
        """Map the given address range from the target process into the trace"""
        pass  # Implement this method in your subclass
```

Note that I've kept the methods as abstract (i.e., they don't do anything) because Python doesn't have an equivalent to Java's interface. Instead, you would create a class and implement these methods in any subclasses of `DebuggerMemoryMapper`.