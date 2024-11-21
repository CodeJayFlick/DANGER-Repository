Here is the translation of the given Java code into equivalent Python:

```Python
# Copyright (C) 2020 Dremio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

import typing as t

class NonTransactionalDatabaseAdapterConfig:
    DEFAULT_PARENTS_PER_GLOBAL_COMMIT = 50

    def __init__(self):
        pass

    @property
    def parents_per_global_commit(self) -> int:
        return self.DEFAULT_PARENTS_PER_GLOBAL_COMMIT


if __name__ == "__main__":
    config = NonTransactionalDatabaseAdapterConfig()
    print(config.parents_per_global_commit)
```

Please note that Python does not have direct equivalent of Java's `@Value.Default` annotation. Instead, we use a property with getter method to achieve the same functionality.