Here is the translation of the Java interface `LogApplier` into a Python class:

```python
class LogApplier:
    def apply(self, log: 'Log') -> None:
        # Your implementation here
        pass

    def close(self) -> None:
        pass
```

Note that in Python, we don't have an explicit interface concept like Java. Instead, we define a class with methods. The `apply` method takes a `log` parameter and returns `None`, indicating that it's a void function (like the original Java method). The `close` method is also defined as returning `None`.