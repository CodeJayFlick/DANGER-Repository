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
