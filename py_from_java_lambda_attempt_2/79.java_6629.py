Here's how you can translate this Java interface into a Python class:

```Python
class DebuggerInterpreterConnection:
    def __init__(self):
        pass

    def set_pinned(self, pinned: bool) -> None:
        pass  # TO DO: implement the method

    def is_pinned(self) -> bool:
        return False  # TO DO: implement the method

    def get_target_console(self) -> object:
        raise NotImplementedError("Method not implemented")

    def get_interpreter_console(self) -> object:
        raise NotImplementedError("Method not implemented")
```

Note that this Python class does not have direct equivalents for Java's `void` and `boolean` return types. In Python, methods can return any type of value (including None), so we've used the `-> None` syntax to indicate that these methods do not return a specific type.

Also note that in Python, you don't need to declare method parameters like you would in Java. The parameter names are optional and are only needed for documentation purposes.