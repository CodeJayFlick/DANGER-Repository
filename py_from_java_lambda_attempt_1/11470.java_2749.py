Here is the equivalent Python code:

```Python
class SledException(Exception):
    def __init__(self, e=None):
        if e:
            super().__init__(e.getMessage())
        else:
            super().__init__()

    @classmethod
    def from_string(cls, message):
        return cls(message)
```

Note that in Python, we don't need to specify the `extends` keyword as it is automatically handled by inheritance. Also, there's no direct equivalent of Java's `@param` and `@return` comments; these are used for documentation purposes only.

The constructor (`__init__`) takes an optional argument `e`, which can be any exception object (like in the original code). If this parameter is provided, it uses that exception message. Otherwise, it creates a new SledException with no detail message.

Additionally, I added another method `from_string` to create a SledException from a string directly.