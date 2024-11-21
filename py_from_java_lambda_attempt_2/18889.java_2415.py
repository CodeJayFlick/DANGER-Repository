Here is the translation of the given Java code into equivalent Python:

```Python
# Copyright (C) 2020 Dremio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

import NessieDbAdapterName
from NessieExternalDatabase import H2TestConnectionProviderSource
from DatabaseAdapterFactory import H2DatabaseAdapterFactory

class TestJerseyResteasyH2:
    def __init__(self):
        self.NessieDbAdapterName = NessieDbAdapterName(H2DatabaseAdapterFactory.NAME)
        self.NessieExternalDatabase = H2TestConnectionProviderSource()

# Note: Python does not have direct equivalent of Java's annotations.
```

Please note that the translation is not a straightforward one-to-one mapping. The `@NessieDbAdapterName` and `@NessieExternalDatabase` are annotation in Java, which do not exist directly in Python.