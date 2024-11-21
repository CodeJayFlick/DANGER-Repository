Here is the equivalent Python code:

```Python
import os
import random

class TestConstant:
    BASE_OUTPUT_PATH = "target" + os.sep
    PARTIAL_PATH_STRING = "%s{}{}/{}"
    TEST_TSFILE_PATH = BASE_OUTPUT_PATH + "testTsFile" + os.sep + PARTIAL_PATH_STRING.format("", 0, 0)

    FLOAT_MIN_DELTA = 1e-5
    DOUBLE_MIN_DELTA = 1e-5

    @classmethod
    def get_random(cls):
        return random.Random(os.urandom(4)).randint(0, 2**31 - 1)
```

Note that Python does not have direct equivalents for Java's `public static final` fields or the concept of a package. The equivalent in Python is to define these as class attributes and use a class method if you want them to be reusable across instances.

Also note that there are some differences between how file paths work in Java versus Python, which I've tried to account for above.