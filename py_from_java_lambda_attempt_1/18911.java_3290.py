Here is the translation of the given Java code into equivalent Python:

```Python
# Copyright (C) 2020 Dremio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

import singleton_decorator as sd

class QuarkusInmemoryStore:
    pass

QuarkusInmemoryStore = sd.Singleton()(QuarkusInmemoryStore)
```

Please note that Python does not have direct equivalent to Java's Singleton annotation. The above code uses `singleton_decorator` which is a third-party library in Python, and it provides the functionality similar to Java's @Singleton.

The InmemoryStore class itself has been translated into a simple Python class with no specific implementation as there was none provided in the original Java code.