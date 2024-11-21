Here is the translation of the given Java code into equivalent Python:

```Python
import typing as t

class DebuggerTargetObjectIface:
    def __init__(self):
        pass

    @property
    def value(self) -> str:
        raise NotImplementedError("Must be implemented by subclass")
```

Please note that this is not a direct translation, but rather an equivalent Python class. The Java code was annotated with `@Retention` and `@Target`, which are used to specify the retention policy and target type for annotations in Java. In Python, we don't have built-in support for these types of annotations like Java does.