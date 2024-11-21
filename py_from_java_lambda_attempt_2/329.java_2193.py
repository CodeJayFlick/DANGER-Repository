Here is the translation of the given Java interface into a Python class:

```Python
class TraceRecorderListener:
    def register_bank_mapped(self, recorder):
        pass

    def register_accessibility_changed(self, recorder):
        pass

    def process_memory_accessibility_changed(self, recorder):
        pass

    def recording_stopped(self, recorder):
        pass

    def snap_advanced(self, recorder, snap):
        pass
```

Note that in Python, we don't have a direct equivalent of Java's `default` keyword for methods. Instead, the method is simply defined with no implementation (i.e., it does nothing).