import unittest
from math import inf


class OpBehaviorIntOrTest(unittest.TestCase):

    def testEvaluateBinaryLong(self):
        op = OpBehaviorIntOr()

        self.assertEqual(0, op.evaluate_binary(4, 4, 0, 0))
        self.assertEqual(1, op.evaluate_binary(4, 4, 1, 0))
        self.assertEqual(1, op.evaluate_binary(4, 4, 0, 1))
        self.assertEqual(inf, op.evaluate_binary(4, 4, inf, 0))
        self.assertEqual(inf, op.evaluate_binary(4, 4, 0, inf))
        self.assertEqual(inf, op.evaluate_binary(4, 4, inf, 1))
        self.assertEqual(inf, op.evaluate_binary(4, 4, 1, inf))
        self.assertEqual(inf, op.evaluate_binary(4, 4, inf, inf))  # overflow
        self.assertEqual(-2**31-1, op.evaluate_binary(8, 8, -2**31-1, 0))
        self.assertEqual(-2**31-1, op.evaluate_binary(8, 8, 0, -2**31-1))
        self.assertEqual(-2**31, op.evaluate_binary(8, 8, -2**31, 1))  # overflow
        self.assertEqual(-2**31, op.evaluate_binary(8, 8, 1, -2**31))  # overflow

    def testEvaluateBinaryBigInteger(self):
        op = OpBehaviorIntOr()

        zero = int('0', 16)
        one = int('1', 16)
        negative_one = int('-1', 16)

        big_positive = int('7FFFFFFFFFFFFFFF', 16)
        big_negative = int('80000000000000000000000000000000', 16)

        self.assertEqual(0, op.evaluate_binary(1, 16, zero, zero))
        self.assertEqual(one, op.evaluate_binary(1, 16, one, zero))
        self.assertEqual(one, op.evaluate_binary(1, 16, zero, one))
        self.assertEqual(negative_one, op.evaluate_binary(1, 16, negative_one, zero))
        self.assertEqual(negative_one, op.evaluate_binary(1, 16, zero, negative_one))
        self.assertEqual(negative_one, op.evaluate_binary(1, 16, negative_one, one))
        self.assertEqual(negative_one, op.evaluate_binary(1, 16, one, negative_one))
        self.assertEqual(negative_one, op.evaluate_binary(1, 16, negative_one, negative_one))

        self.assertEqual(big_negative, op.evaluate_binary(1, 16, big_negative, zero))
        self.assertEqual(big_negative, op.evaluate_binary(1, 16, zero, big_negative))
        self.assertEqual(big_positive + one, op.evaluate_binary(1, 16, big_negative, one))  # overflow
        self.assertEqual(big_positive + one, op.evaluate_binary(1, 16, one, big_negative))  # overflow

        self.assertEqual(negative_one, op.evaluate_binary(1, 16, big_negative, big_positive))
        self.assertEqual(negative_one, op.evaluate_binary(1, 16, big_positive, big_negative))

        self.assertEqual(big_negative, op.evaluate_binary(1, 16, big_negative, big_negative))  # overflow
        self.assertEqual(big_positive, op.evaluate_binary(1, 16, big_positive, big_positive))  # overflow


if __name__ == '__main__':
    unittest.main()
