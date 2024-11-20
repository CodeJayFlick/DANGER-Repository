Here is the translation of the given Java code into equivalent Python:

```Python
class DbgCommandRunningEvent:
    def __init__(self):
        pass  # equivalent to super() in Java

    def new_state(self) -> str:
        return "RUNNING"
```

Note that this is a simplified version, as there are some differences between the two languages. For example:

- In Python, we don't need an `@Override` annotation for overriding methods.
- The equivalent of Java's `DbgState.RUNNING` would be `"RUNNING"` in Python (as strings).
- We use `pass` to indicate that a method does nothing, as there is no direct equivalent of the empty constructor (`super()`) in Python.