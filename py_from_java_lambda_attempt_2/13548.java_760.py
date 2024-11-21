Here is the translation of the given Java code into equivalent Python:

```Python
class IsolatedFailPluginB:
    ERROR_MSG = "Isolated Fail Plugin B error message"

    def __init__(self):
        pass

    def init(self):
        raise RuntimeError(self.ERROR_MSG)
```

Note that this Python code does not exactly replicate the original Java code. The `@PluginInfo` annotation and other Java-specific constructs are not directly translatable to Python, as they rely on specific features of the Java programming language (such as annotations).