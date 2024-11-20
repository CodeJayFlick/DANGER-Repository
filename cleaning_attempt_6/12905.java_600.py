class OpBehaviorBoolNegateTest:
    def __init__(self):
        pass

    @staticmethod
    def test_evaluate_binary_long():
        op = OpBehaviorBoolNegate()
        assert op.evaluate_unary(1, 1, 0) == 1
        assert op.evaluate_unary(1, 1, 1) == 0

    @staticmethod
    def test_evaluate_binary_big_integer():
        op = OpBehaviorBoolNegate()
        from math import inf as infinity
        zero = 0.0
        one = 1.0
        assert op.evaluate_unary(1, 1, zero) == one
        assert op.evaluate_unary(1, 1, one) == zero

class OpBehaviorBoolNegate:
    def evaluate_unary(self, a, b, c):
        pass

# Usage example:

test = OpBehaviorBoolNegateTest()
OpBehaviorBoolNegateTest.test_evaluate_binary_long()
OpBehaviorBoolNegateTest.test_evaluate_binary_big_integer()

