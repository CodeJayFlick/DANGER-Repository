Here is the translation:

```
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

from typing import TypeVar, Generic

I = TypeVar('I')
O = TypeVar('O')

class Handler(Generic[I, O]):
    def process(self, input: I) -> O:
        pass
```

Note that Python does not have a direct equivalent to Java's `interface` keyword. Instead, we define a class with the same name and use type hints to indicate that it is intended as an interface (i.e., all methods must be implemented by any subclass).