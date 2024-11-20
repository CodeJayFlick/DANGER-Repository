Here is the translation of the given Java code into equivalent Python:

```Python
class FlushListener:
    def on_flush_start(self, mem_table):
        pass

    def on_flush_end(self, mem_table):
        pass


class EmptyListener(FlushListener):
    INSTANCE = EmptyListener()

    def __init__(self):
        pass

    def on_flush_start(self, mem_table):
        # do nothing
        pass

    def on_flush_end(self, mem_table):
        # do nothing
        pass
```

Note that Python does not have a direct equivalent to Java's `interface` or `class EmptyListener implements FlushListener`. Instead, we define an abstract base class (`FlushListener`) and then create another concrete subclass (`EmptyListener`).