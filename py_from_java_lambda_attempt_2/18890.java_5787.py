Here is the translation of the Java code to Python:

```
# Copyright (C) 2020 Dremio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

import abc

class NessieDbAdapterName:
    NAME = 'InmemoryDatabaseAdapterFactory'

class NessieExternalDatabase:
    pass

class TestJerseyResteasyInMemory(abc.ABC):
    @NessieDbAdapterName.NAME
    @NessieExternalDatabase
    def __init__(self):
        super().__init__()
```

Note that Python does not have direct equivalents to Java's annotations (`@` syntax), so I've replaced them with simple class and method definitions. The `abc.ABC` mixin is used to indicate that the class is abstract, similar to how it would be done in Java using the `abstract` keyword.