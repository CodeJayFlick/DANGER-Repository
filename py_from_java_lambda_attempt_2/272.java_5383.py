Here is the translation of the Java interface into a Python class:

```Python
class ManagedModuleRecorder:
    def offer_process_module(self, module):
        pass  # Implement this method as needed

    def offer_process_module_section(self, section):
        pass  # Implement this method as needed

    def remove_process_module(self, module):
        pass  # Implement this method as needed

    def get_trace_module(self, module):
        return None  # Return a TraceModule instance or None if not implemented

    def get_trace_section(self, section):
        return None  # Return a TraceSection instance or None if not implemented
```

Please note that the `pass` statements are placeholders for actual implementation. You would need to implement these methods according to your specific requirements.