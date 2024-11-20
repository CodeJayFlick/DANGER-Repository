Here's a translation of the provided Java code into equivalent Python:

```Python
# Copyright (C) 2020 Dremio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

import quarkus.runtime.annotations.register_for_reflection

class ModelReflections:
    pass


@register_for_reflection(targets=NessieError)
class AbstractModelReflections(ModelReflections):
    def __init__(self):
        super().__init__()
```

Please note that Python does not have direct equivalents for Java's `package`, `abstract class` and `@RegisterForReflection`.