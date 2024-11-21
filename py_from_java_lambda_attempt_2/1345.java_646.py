Here is the translation of the given Java code into equivalent Python:

```Python
import abc

class GdbGetVarCommand:
    def __init__(self, manager: 'GdbManagerImpl', var_name: str):
        self.manager = manager
        self.var_name = var_name

    @abc.abstractmethod
    def encode(self) -> str:
        return f"-gdb-show {self.var_name}"

    def complete(self, pending_command: object) -> str | None:
        if isinstance(pending_command, GdbCommandDoneEvent):
            return getattr(pending_command, 'maybe_value', None)
```

Note that Python does not have direct equivalent of Java's `package`, `public class`, etc. statements. Also, Python is dynamically typed and does not require explicit type declarations for variables or method parameters.

In the above code:

- The `GdbGetVarCommand` class has been defined with an initializer (`__init__`) that takes a `manager` of type `'GdbManagerImpl'` (note: this is just a string, Python doesn't have strong typing like Java) and a `var_name` of type `str`.
- The `encode` method returns the encoded command as a string.
- The `complete` method checks if the given `pending_command` is an instance of `GdbCommandDoneEvent`, then tries to get its value. If it's not, or if there's no such attribute, it returns `None`.