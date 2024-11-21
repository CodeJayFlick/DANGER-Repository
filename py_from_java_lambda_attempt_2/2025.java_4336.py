Here is the translation of the Java interface `JdiModelTargetEnvironment` into a Python class:

```python
from abc import ABC, abstractmethod


class JdiModelTargetEnvironment(ABC):
    def refresh_internal(self):
        pass  # No equivalent in Python for this method

    @abstractmethod
    def get_architecture(self) -> str:
        raise NotImplementedError("Method not implemented")

    @abstractmethod
    def get_debugger(self) -> str:
        raise NotImplementedError("Method not implemented")

    @abstractmethod
    def get_operating_system(self) -> str:
        raise NotImplementedError("Method not implemented")
```

Note that:

* In Python, we don't need to specify the `public` access modifier as it's implicit.
* The `@Override` annotation is not necessary in Python since method overriding works differently than in Java.
* We've replaced the `default` keyword with an abstract method (`@abstractmethod`) and implemented a simple placeholder for the `refreshInternal()` method, which doesn't have a direct equivalent in Python.