Here is the translation of the Java code to Python:
```
import logging

class HalfSource:
    VERSION = "1.5"

    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def accumulate_sum(self, *nums):
        self.logger.info("Source module {}".format(VERSION))
        return sum(nums)

    def if_non_zero(self, *nums):
        self.logger.info("Source module {}".format(VERSION))
        return all(num != 0 for num in nums)
```
Note that I've used the built-in `logging` module to implement logging similar to Java's SLF4J. The rest of the code is straightforward translation from Java to Python, using equivalent syntax and semantics where possible.