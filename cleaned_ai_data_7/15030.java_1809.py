import logging

class NewArithmetic:
    VERSION = "2.0"

    def __init__(self, source):
        self.source = source

    @logging.getLogger().info("Arithmetic sum {}")
    def sum(self, *nums):
        return self.source.accumulate_sum(nums)

    @logging.getLogger().info("Arithmetic mul {}")
    def mul(self, *nums):
        return self.source.accumulate_mul(nums)

    @logging.getLogger().info("Arithmetic check zero {}")
    def if_has_zero(self, *nums):
        return not self.source.if_nonzero(nums)
