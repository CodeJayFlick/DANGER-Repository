Here is the translation of the Java code to Python:

```Python
import logging

class NewSource:
    VERSION = "2.0"
    SOURCE_MODULE = "{}"

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.info(SOURCE_MODULE.format("New Source"), VERSION)

    def accumulate_sum(self, *nums):
        return sum(nums)

    def accumulate_mul(self, *nums):
        result = 1
        for num in nums:
            result *= num
        return result

    def if_non_zero(self, *nums):
        return all(num != 0 for num in nums)
```

Note that Python does not have a direct equivalent to Java's `@Slf4j` annotation. Instead, we create a logger object and use it throughout the class. The logging statements are similar to those in the original code.

The `accumulate_sum` method is translated from the Java stream-based implementation to a simple sum using the built-in Python function `sum`.

The `accumulate_mul` method uses a loop instead of a stream, as there isn't an equivalent way to perform multiplication with a stream in Python.