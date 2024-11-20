Here is the translation of the Java code to Python:
```
class TraceClosedPluginEvent:
    NAME = "Trace Closed @"

    def __init__(self, source, trace):
        super().__init__(source, f"{NAME}{hex(id(trace))}")
        self.trace_ref = weakref.ref(trace)

    def get_trace(self):
        return self.trace_ref()
```
Note that I used the `weakref` module to implement the equivalent of Java's `WeakReference`. In Python, you can use a function reference as a "weak" reference by using the `weakref.ref()` constructor.