Here is the translation of the given Java code into equivalent Python:

```Python
# Copyright (C) 2020 Dremio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

import abc

class NessieExternalDatabase:
    def __init__(self, provider):
        self.provider = provider

@NessieExternalDatabase(RocksTestConnectionProviderSource)
class TestVersionStoreRocks(abc.ABCMeta('AbstractVersionStoreTest')):
    pass
```

Please note that Python does not have direct equivalent of Java's `package` statement. Also, the concept of abstract classes and interfaces is different in Python compared to Java. In this translation, I've used ABC (Abstract Base Classes) module from Python standard library which provides a way to create abstract base classes.