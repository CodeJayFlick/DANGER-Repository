Here is the translation of the given Java code into equivalent Python:

```Python
class User:
    def __init__(self, username: str):
        self.username = username

from dataclasses import dataclass, field

@dataclass(frozen=True)
class User:
    username: str
```

Please note that there is no direct translation of the Java `lombok` annotations (`Getter`, `RequiredArgsConstructor`) to Python. The equivalent way in Python would be using the built-in `__init__` method for initialization and dataclasses from the standard library, which can simplify object creation.

The first example uses a regular class with an initializer function (`__init__`).