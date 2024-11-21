import unittest
from math import inf


class OpBehaviorIntCarryTest(unittest.TestCase):

    def testEvaluateBinaryLong(self):
        op = OpBehaviorIntCarry()

        self.assertEqual(0, op.evaluate_binary(4, 4, 0, 0))
        self.assertEqual(1, op.evaluate_binary(4, 4, 1, inf - 1))
        self.assertEqual(1, op.evaluate_binary(4, 4, inf - 1, 1))
        self.assertEqual(0, op.evaluate_binary(4, 4, inf - 2**31, -2**31))
        self.assertEqual(1, op.evaluate_binary(4, 4, inf - 2**31, inf - 2**30 + 1))
        self.assertEqual(0, op.evaluate_binary(4, 4, -2**31, inf - 2**31))
        self.assertEqual(1, op.evaluate_binary(4, 4, -2**31 + 1, inf - 2**31))

        self.assertEqual(0, op.evaluate_binary(8, 8, 0, 0))
        self.assertEqual(0, op.evaluate_binary(8, 8, inf, -inf))
        self.assertEqual(1, op.evaluate_binary(8, 8, inf, -inf + 1))
        self.assertEqual(0, op.evaluate_binary(8, 8, -inf, inf))
        self.assertEqual(1, op.evaluate_binary(8, 8, -inf + 1, inf))

    def testEvaluateBinaryBigInteger(self):
        op = OpBehaviorIntCarry()

        zero_big_int = int('FFFFFFFFFFFFFFFF', 16)
        big_positive = int('7FFFFFFFFFFFFFFF', 16)
        big_negative = int('8000000000000000', 16)

        self.assertEqual(0, op.evaluate_binary(8, 8, 0, 0))
        self.assertEqual(1, op.evaluate_binary(8, 8, 1, zero_big_int - 1))
        self.assertEqual(1, op.evaluate_binary(8, 8, zero_big_int - 1, 1))
        self.assertEqual(0, op.evaluate_binary(8, 8, big_positive, big_negative))
        self.assertEqual(1, op.evaluate_binary(8, 8, big_positive, big_negative + 1))
        self.assertEqual(0, op.evaluate_binary(8, 8, big_negative, big_positive))
        self.assertEqual(1, op.evaluate_binary(8, 8, big_negative + 1, big_positive))


if __name__ == '__main__':
    unittest.main()
