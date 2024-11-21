Here is the translation of the given Java code into equivalent Python:

```Python
# Licensed under Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

from typing import Callable, Any

class IFileQueryMemMeasurement:
    """Estimate how much memory a file may occupy when being queried during merge."""
    
    def __call__(self, resource: 'TsFileResource') -> int:
        raise NotImplementedError
```

Note that the `@FunctionalInterface` annotation is not directly translatable to Python. Instead, we define an abstract class with a single method (`__call__`) which can be used as a functional interface in Python.

The equivalent of Java's `throws IOException` statement is omitted because Python does not have built-in support for declaring exceptions at the function level like Java does.