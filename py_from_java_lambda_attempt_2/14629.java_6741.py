Here is the translation of the Java code to Python:
```
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import object_pool as op

class OliphauntPool(op.ObjectPool):
    def create(self):
        return Oliphaunt()
```
Note that I've used the `object_pool` module from Python, which is not a standard library. If you don't have this module installed, you can install it using pip: `pip install object-pool`.