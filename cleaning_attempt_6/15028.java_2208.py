import logging

class HalfArithmetic:
    VERSION = "1.5"

    def __init__(self, new_source: 'HalfSource', old_source: 'OldSource'):
        self.new_source = new_source
        self.old_source = old_source

    @logging.info("Arithmetic sum {}", VERSION)
    def sum(self, *nums):
        return self.new_source.accumulate_sum(nums)

    @logging.info("Arithmetic mul {}", VERSION)
    def mul(self, *nums):
        return self.old_source.accumulate_mul(nums)

    @logging.info("Arithmetic check zero {}", VERSION)
    def if_has_zero(self, *nums):
        return not self.new_source.if_nonzero(nums)
