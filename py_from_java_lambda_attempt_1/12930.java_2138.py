Here is the translation of the given Java code into Python:

```Python
import unittest
from math import inf


class OpBehaviorIntDivTest(unittest.TestCase):

    def testEvaluateBinaryLong(self):
        op = OpBehaviorIntDiv()

        self.assertEqual(0, op.evaluate_binary(4, 4, 1, 0))  # divide by zero

        self.assertEqual(13, op.evaluate_binary(4, 4, 65, 5))
        self.assertEqual(0, op.evaluate_binary(4, 4, 0, 1))
        self.assertEqual(0, op.evaluate_binary(4, 4, 0, inf))  # equivalent to divide by zero
        self.assertEqual(inf, op.evaluate_binary(4, 4, inf, 1))
        self.assertEqual(0, op.evaluate_binary(4, 4, 1, inf))
        self.assertEqual(1, op.evaluate_binary(4, 4, inf, inf))  # equivalent to divide by zero
        self.assertEqual(0, op.evaluate_binary(4, 4, 0x80000000L, 0))  # negative number division
        self.assertEqual(0x80000000L, op.evaluate_binary(4, 4, 0x80000000L, 1))
        self.assertEqual(0, op.evaluate_binary(4, 4, 1, 0x80000000L))
        self.assertEqual(1, op.evaluate_binary(4, 4, 0x80000000L, inf))  # equivalent to divide by zero
        self.assertEqual(0, op.evaluate_binary(4, 4, -inf, 0))  # negative number division
        self.assertEqual(-inf, op.evaluate_binary(4, 4, -inf, 1))
        self.assertEqual(0, op.evaluate_binary(4, 4, 1, -inf))
        self.assertEqual(1, op.evaluate_binary(4, 4, inf, inf))  # equivalent to divide by zero

    def testEvaluateBinaryBigInteger(self):
        op = OpBehaviorIntDiv()

        big_negative_one = int('7FFFFFFFFFFFFFFF', 16)
        big_positive = int('80000000000000000000000000000000', 16)

        self.assertEqual(0, op.evaluate_binary(1, 16, 1, 0))  # divide by zero

        self.assertEqual(int('3E0708EE', 16), op.evaluate_binary(8, 8, int('2512345678L', 16), 99))

        self.assertEqual(0, op.evaluate_binary(1, 16, 0, 1))
        self.assertEqual(0, op.evaluate_binary(1, 16, 0, big_negative_one))  # negative number division
        self.assertEqual(big_negative_one, op.evaluate_binary(1, 16, big_negative_one, 1))
        self.assertEqual(0, op.evaluate_binary(1, 16, 1, big_negative_one))
        self.assertEqual(1, op.evaluate_binary(1, 16, big_negative_one, big_positive))  # equivalent to divide by zero
        self.assertEqual(0, op.evaluate_binary(1, 16, 0, -inf))  # negative number division
        self.assertEqual(-inf, op.evaluate_binary(1, 16, -inf, 1))
        self.assertEqual(0, op.evaluate_binary(1, 16, 1, -inf))
        self.assertEqual(1, op.evaluate_binary(1, 16, inf, inf))  # equivalent to divide by zero


if __name__ == '__main__':
    unittest.main()
```

Note: The test cases are not exactly the same as in Java. Some tests were removed or modified due to differences between Python and Java.