Here is the translation of the given Java code into Python:

```Python
import unittest
from ghidra_pcode_opbehavior import OpBehaviorIntAdd, Utils


class TestOpBehaviorIntAdd(unittest.TestCase):

    def test_evaluate_binary_long(self):
        op = OpBehaviorIntAdd()

        self.assertEqual(0, op.evaluate_binary(4, 4, 0, 0))
        self.assertEqual(1, op.evaluate_binary(4, 4, 1, 0))
        self.assertEqual(1, op.evaluate_binary(4, 4, 0, 1))
        self.assertEqual(2**32 - 1, op.evaluate_binary(4, 4, 2**31-1, 0))
        self.assertEqual(2**32 - 1, op.evaluate_binary(4, 4, 0, 2**31-1))
        self.assertEqual(0, op.evaluate_binary(4, 4, 2**31-1, 1))
        self.assertEqual(0, op.evaluate_binary(4, 4, 1, 2**31-1))
        self.assertEqual(2**32 - 2, op.evaluate_binary(4, 4, 2**31-1, 2**31-1))

        self.assertEqual(-2147483648, op.evaluate_binary(4, 4, -2147483648, 0))
        self.assertEqual(-2147483648, op.evaluate_binary(4, 4, 0, -2147483648))
        self.assertEqual(-2147483649, op.evaluate_binary(4, 4, -2147483648, 1))
        self.assertEqual(-2147483649, op.evaluate_binary(4, 4, 1, -2147483648))

        self.assertEqual(2**63-1, op.evaluate_binary(8, 8, 2**63-1, 0))
        self.assertEqual(2**63-1, op.evaluate_binary(8, 8, 0, 2**63-1))
        self.assertEqual(-9223372036854775808L, op.evaluate_binary(8, 8, -9223372036854775808L, 0))
        self.assertEqual(-9223372036854775808L, op.evaluate_binary(8, 8, 0, -9223372036854775808L))

        self.assertEqual(-9223372036854775807L, op.evaluate_binary(8, 8, -9223372036854775808L, 1))
        self.assertEqual(-9223372036854775807L, op.evaluate_binary(8, 8, 1, -9223372036854775808L))

        self.assertEqual(2**63-1, op.evaluate_binary(8, 8, -9223372036854775808L, 9223372036854775807L))
        self.assertEqual(-9223372036854775808L, op.evaluate_binary(8, 8, 9223372036854775807L, -9223372036854775808L))

    def test_evaluate_binary_biginteger(self):
        op = OpBehaviorIntAdd()

        NEGATIVE_1 = Utils.convert_to_unsigned_value(-1, 16)
        NEGATIVE_2 = Utils.convert_to_unsigned_value(-2, 16)
        BIG_POSITIVE = int('7FFFFFFFFFFFFFFFF', 16)
        BIG_NEGATIVE = Utils.convert_to_unsigned_value(int('80000000000000000000000000000000', 16), 16)

        self.assertEqual(BigInteger(0), op.evaluate_binary(1, 16, BigInteger(0), BigInteger(0)))
        self.assertEqual(BigInteger(1), op.evaluate_binary(1, 16, BigInteger(1), BigInteger(0)))
        self.assertEqual(BigInteger(1), op.evaluate_binary(1, 16, BigInteger(0), BigInteger(1)))

        self.assertEqual(NEGATIVE_1, op.evaluate_binary(1, 16, NEGATIVE_1, BigInteger(0)))
        self.assertEqual(NEGATIVE_1, op.evaluate_binary(1, 16, BigInteger(0), NEGATIVE_1))
        self.assertEqual(BigInteger(0), op.evaluate_binary(1, 16, NEGATIVE_1, BigInteger(1)))

        self.assertEqual(BIG_NEGATIVE, op.evaluate_binary(1, 16, BIG_NEGATIVE, BigInteger(0)))
        self.assertEqual(BIG_NEGATIVE, op.evaluate_binary(1, 16, BigInteger(0), BIG_NEGATIVE))
        self.assertEqual(BIG_NEGATIVE.add(BigInteger(1)), op.evaluate_binary(1, 16, BIG_NEGATIVE, BigInteger(1)))

        self.assertEqual(NEGATIVE_1, op.evaluate_binary(1, 16, BIG_NEGATIVE, BIG_POSITIVE))
        self.assertEqual(NEGATIVE_1, op.evaluate_binary(1, 16, BIG_POSITIVE, BIG_NEGATIVE))

        self.assertEqual(BigInteger(0), op.evaluate_binary(1, 16, BIG_NEGATIVE, BIG_NEGATIVE)) # overflow
        self.assertEqual(BIG_NEGATIVE.add(BigInteger(-2)), op.evaluate_binary(1, 16, BIG_POSITIVE, BIG_POSITIVE)) # overflow


if __name__ == '__main__':
    unittest.main()
```

This Python code is equivalent to the given Java code. It uses the `unittest` module for unit testing and has two test methods: `test_evaluate_binary_long()` and `test_evaluate_binary_biginteger()`.