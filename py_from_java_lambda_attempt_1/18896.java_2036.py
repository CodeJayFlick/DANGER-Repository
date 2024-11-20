Here is the translation of the given Java code into equivalent Python:

```Python
# Copyright (C) 2020 Dremio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

import rocksdb as RocksDatabaseAdapterFactory
from extension import NessieDbAdapterName, NessieExternalDatabase

class TestJerseyRestRocks:
    @NessieDbAdapterName(RocksDatabaseAdapterFactory.NAME)
    @NessieExternalDatabase(RocksTestConnectionProviderSource.__name__)
    def __init__(self):
        super().__init__()
```

Please note that Python does not have direct equivalent of Java's package, import statements or annotations. The given code is a translation and might require some adjustments based on the actual use case in your project.

Also, `RocksTestConnectionProviderSource` seems to be missing from the provided Java code, so I've used its name as a string for demonstration purposes only. You would need to replace this with an equivalent Python class or object if you're using it elsewhere in your program.