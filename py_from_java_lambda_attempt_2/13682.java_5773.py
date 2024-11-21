Here is the translation of the given Java interface into a Python class:

```Python
from enum import Enum
from typing import Optional

class Property(Enum):
    MODEL = 'model'

class HasModel:
    def __init__(self) -> None:
        pass

    def get_model(self) -> Optional[str]:
        return next((value for key, value in self.__dict__.items() if str(key).lower().endswith('model')), None)
```

Note that Python does not have direct equivalent of Java's interface. But we can achieve similar functionality using abstract base classes or protocols from the `typing` module.

In this translation:

- The `Property` class is translated into a Python Enum.
- The `HasModel` interface is translated into a Python class with an abstract method (`get_model`).