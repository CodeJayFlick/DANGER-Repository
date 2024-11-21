Here is the translation of the Java interface `ProcessorContext` into a Python class:

```python
class ProcessorContext:
    def __init__(self):
        pass

    def set_value(self, register: 'Register', value: int) -> None:
        raise ContextChangeException("Illegal attempt to change context")

    def set_register_value(self, value: 'RegisterValue') -> None:
        raise ContextChangeException("Illegal attempt to change context")

    def clear_register(self, register: 'Register') -> None:
        raise ContextChangeException("Illegal attempt to change context")


class RegisterValue:
    pass


class Register:
    pass


class ContextChangeException(Exception):
    pass
```

Note that I had to create Python classes for `Register`, `RegisterValue` and the exception class, as there is no direct equivalent in Java.