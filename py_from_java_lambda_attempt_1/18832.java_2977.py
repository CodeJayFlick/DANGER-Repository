Here is a translation of the Java interface into equivalent Python code:

```Python
from typing import Dict, Any

class HttpConfigApi:
    def __init__(self):
        pass

    @property
    def config(self) -> Dict[str, Any]:
        return self._config

    @config.setter
    def config(self, value: NessieConfiguration) -> None:
        self._config = value


def get_config() -> NessieConfiguration:
    # implement the logic to retrieve configuration settings here
    pass
```

Please note that this is a direct translation of Java code into Python. The equivalent Python class does not have an interface, but it has similar functionality.

Here are some key differences between Java and Python:

1. In Java, you need to explicitly define methods as `@Override` when overriding the method from parent class or interface. However, in Python, there is no such requirement.
2. Java uses annotations like `@Path`, `@GET`, etc., which do not have direct equivalents in Python. Instead, we can use decorators for similar functionality.

Here's how you could implement a decorator to achieve similar behavior:

```Python
def path(path: str):
    def decorator(func):
        func.__path = path
        return func
    return decorator

@path("/config")
class HttpConfigApi:
    # method implementation here
```

However, please note that Python does not support the exact equivalent of Java's `@Path` annotation.