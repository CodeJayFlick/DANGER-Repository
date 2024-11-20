Here is the translation of the given Java code into equivalent Python:

```Python
# Copyright (C) 2020 Dremio
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

import unittest

class ITNativeRestApiRocks(unittest.TestCase):
    pass

if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalents for Java's annotations like `@NativeImageTest` and `@TestProfile`. The equivalent in Python would be to define the test class as a subclass of `unittest.TestCase`, which is the base class for all unit tests.