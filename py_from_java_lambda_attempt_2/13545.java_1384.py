Here is a translation of the provided Java code into equivalent Python:

```Python
class InitFailPluginB:
    ERROR_MSG = "PluginB fails during Plugin.init()"
    dispose_count = 0

    def __init__(self):
        pass

    def init(self):
        raise RuntimeError(ERROR_MSG)

    def dispose(self):
        self.dispose_count += 1


# Note: Python does not have direct equivalent of Java's @PluginInfo, so I did not include it.
```

Please note that this is a simple translation and might require additional work to be fully compatible with the original code.