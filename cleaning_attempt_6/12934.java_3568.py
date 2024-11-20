import unittest
from ghidra_pcode_opbehavior import OpBehaviorIntMult


class TestOpBehaviorIntMult(unittest.TestCase):

    def test_evaluate_binary_long(self):
        op = OpBehaviorIntMult()

        self.assertEqual(0, op.evaluate_binary(4, 4, 0, 0))
        self.assertEqual(0, op.evaluate_binary(4, 4, 1, 0))
        self.assertEqual(0, op.evaluate_binary(4, 4, 0, 1))
        self.assertEqual(0, op.evaluate_binary(4, 4, 0xffffffffL, 0))
        self.assertEqual(0, op.evaluate_binary(4, 4, 0, 0xffffffffL))
        self.assertEqual(0xffffffffL, op.evaluate_binary(4, 4, 0xffffffffL, 1))
        self.assertEqual(0xffffffffL, op.evaluate_binary(4, 4, 1, 0xffffffffL))
        self.assertEqual(1, op.evaluate_binary(4, 4, 0xffffffffL, 0xffffffffL))
        self.assertEqual(0, op.evaluate_binary(4, 4, 0x80000000L, 0))
        self.assertEqual(0, op.evaluate_binary(4, 4, 0, 0x80000000L))
        self.assertEqual(0x80000000L, op.evaluate_binary(4, 4, 0x80000000L, 1))
        self.assertEqual(0x80000000L, op.evaluate_binary(4, 4, 1, 0x80000000L))
        self.assertEqual(0x80000000L, op.evaluate_binary(4, 4, 0x80000000L, 0x7fffffffL), 4)
        self.assertEqual(0x80000000L, op.evaluate_binary(4, 4, 0x7fffffffL, 0x80000000L))
        self.assertEqual(0, op.evaluate_binary(4, 4, 0x80000000L, 0x80000000L))
        self.assertEqual(1, op.evaluate_binary(4, 4, 0x7fffffffL, 0x7fffffffL))
        self.assertEqual(0x71c71c72, op.evaluate_binary(4, 4, 0x55555555L, 0xaaaaaaaaL))

        self.assertEqual(0, op.evaluate_binary(8, 8, 0, 0))
        self.assertEqual(0, op.evaluate_binary(8, 8, 1, 0))
        self.assertEqual(0, op.evaluate_binary(8, 8, 0, 1))
        self.assertEqual(0, op.evaluate_binary(8, 8, -1, 0))
        self.assertEqual(0, op.evaluate_binary(8, 8, 0, -1))
        self.assertEqual(-1, op.evaluate_binary(8, 8, -1, 1))
        self.assertEqual(-1, op.evaluate_binary(8, 8, 1, -1))
        self.assertEqual(1, op.evaluate_binary(8, 8, -1, -1))
        self.assertEqual(0, op.evaluate_binary(8, 8, int('7fffffff'), 0))
        self.assertEqual(0, op.evaluate_binary(8, 8, 0, int('7fffffff')))
        self.assertEqual(int('71c71c72', 16), op.evaluate_binary(8, 8, int('55555555', 16), int('aaaaaaaa', 16)))

    def test_evaluate_binary_big_integer(self):
        op = OpBehaviorIntMult()

        big_negative = int('80000000000000000000000000000000', 16)
        big_positive = int('7fffffffffffffff', 16)

        self.assertEqual(int(0, 2), op.evaluate_binary(1, 16, int(0, 2), int(0, 2)), 16)
        self.assertEqual(int(1, 2), op.evaluate_binary(1, 16, int(1, 2), int(0, 2)), 16)
        self.assertEqual(int(0, 2), op.evaluate_binary(1, 16, int(0, 2), int(1, 2)), 16)
        self.assertEqual(int(-1, 2), op.evaluate_binary(1, 16, int(-1, 2), int(0, 2)), 16)
        self.assertEqual(int(0, 2), op.evaluate_binary(1, 16, int(0, 2), int(-1, 2)), 16)
        self.assertEqual(int(-1, 2), op.evaluate_binary(1, 16, int(-1, 2), int(-1, 2)), 16)
        self.assertEqual(big_negative, op.evaluate_binary(1, 16, big_negative, int(1, 2)), 16)
        self.assertEqual(big_negative, op.evaluate_binary(1, 16, int(1, 2), big_negative), 16)
        self.assertEqual(big_positive, op.evaluate_binary(1, 16, big_positive, int(-1, 2)), 16)
        self.assertEqual(big_negative, op.evaluate_binary(1, 16, big_negative, big_positive), 16)
        self.assertEqual(int('71c71c72', 16), op.evaluate_binary(8, 8, int('55555555', 16), int('aaaaaaaa', 16)), 16)


if __name__ == '__main__':
    unittest.main()
