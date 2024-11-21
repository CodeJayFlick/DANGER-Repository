Here is a translation of the given Java interface into equivalent Python code:

```Python
from typing import CompletableFuture, Any

class TargetDataType:
    pass

class DataTypeManager:
    def __init__(self):
        self.data_types = {}

    def get_data_type(self) -> Any:
        return None


class Address:
    NO_ADDRESS = object()

    def is_constant_address(self) -> bool:
        return False
```

Here's a brief explanation of the translation:

- The Java interface `TargetSymbol` has been translated into Python class with similar methods.
- The types in Java like `CompletableFuture`, `TargetDataType`, and `Address` have been replaced by equivalent classes or objects in Python. Note that these are placeholder classes, as their actual implementation would depend on specific requirements of your application.
- In the translation process, I've used type hints to indicate the expected return types for methods where applicable.

Please note that this is a direct translation and may not be perfect since Java and Python have different syntaxes and semantics.