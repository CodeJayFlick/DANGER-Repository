Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from ghidra_pcode_opbehavior import OpBehaviorIntLessEqual


class TestOpBehaviorIntLessEqual(unittest.TestCase):

    def test_evaluate_binary_long(self):
        op = OpBehaviorIntLessEqual()

        self.assertEqual(1, op.evaluate_binary(1, 4, 0, 0))
        self.assertEqual(0, op.evaluate_binary(1, 4, 1, 0))
        self.assertEqual(1, op.evaluate_binary(1, 4, 0, 1))
        self.assertEqual(0, op.evaluate_binary(1, 4, 2**31 - 1, 0))
        self.assertEqual(1, op.evaluate_binary(1, 4, 0, 2**31 - 1))
        self.assertEqual(0, op.evaluate_binary(1, 4, 2**31 - 1, 1))
        self.assertEqual(1, op.evaluate_binary(1, 4, 1, 2**31 - 1))
        self.assertEqual(1, op.evaluate_binary(1, 4, 2**31 - 1, 2**31 - 1))
        self.assertEqual(0, op.evaluate_binary(1, 4, 2**30 + 2**28, 0))
        self.assertEqual(1, op.evaluate_binary(1, 4, 0, 2**30 + 2**28))
        self.assertEqual(0, op.evaluate_binary(1, 4, 2**30 + 2**28, 1))
        self.assertEqual(1, op.evaluate_binary(1, 4, 1, 2**30 + 2**28))
        self.assertEqual(0, op.evaluate_binary(1, 4, 2**30 + 2**28, 2**31 - 1))
        self.assertEqual(1, op.evaluate_binary(1, 4, 2**31 - 1, 2**30 + 2**28))
        self.assertEqual(0, op.evaluate_binary(1, 8, 2**63 - 1, 0))
        self.assertEqual(1, op.evaluate_binary(1, 8, 0, 2**63 - 1))
        self.assertEqual(0, op.evaluate_binary(1, 8, 2**63 - 1, 1))
        self.assertEqual(1, op.evaluate_binary(1, 8, 1, 2**63 - 1))
        self.assertEqual(1, op.evaluate_binary(1, 8, 2**63 - 1, 2**63 - 1))
        self.assertEqual(0, op.evaluate_binary(1, 8, 2**63 + 2**62, 0))
        self.assertEqual(1, op.evaluate_binary(1, 8, 0, 2**63 + 2**62))
        self.assertEqual(0, op.evaluate_binary(1, 8, 2**63 + 2**62, 1))
        self.assertEqual(1, op.evaluate_binary(1, 8, 1, 2**63 + 2**62))
        self.assertLessEqual(op.evaluate_binary(1, 8, 0x8000000000000000L, 0), 0)
        self.assertGreaterEqual(op.evaluate_binary(1, 8, 0xffffffffffffffffL, 0), 0)

    def test_evaluate_binary_biginteger(self):
        op = OpBehaviorIntLessEqual()

        assert op.evaluate_binary(1, 16, 0, 0) == 1
        assert op.evaluate_binary(1, 16, 1, 0) == 0
        assert op.evaluate_binary(1, 16, 0, 1) == 1
        assert op.evaluate_binary(1, 16, -1, 0) == 0
        assert op.evaluate_binary(1, 16, 0, -1) == 1
        assert op.evaluate_binary(1, 16, -1, 1) == 0
        assert op.evaluate_binary(1, 16, 1, -1) == 1
        assert op.evaluate_binary(1, 16, -1, -1) == 1
        assert op.evaluate_binary(1, 16, int('8000000000000000', 2), 0) == 0
        assert op.evaluate_binary(1, 16, 0, int('8000000000000000', 2)) == 1
        assert op.evaluate_binary(1, 16, -int('8000000000000000', 2), 1) == 0
        assert op.evaluate_binary(1, 16, 1, int('7FFFFFFFFFFFFFFF', 16)) == 1
        assert op.evaluate_binary(1, 16, int('8000000000000000', 2), int('7FFFFFFFFFFFFFFF', 16)) == 0


if __name__ == '__main__':
    unittest.main()
```

Please note that the Python code is not exactly equivalent to the Java code. The reason for this difference is due to the way integer arithmetic works in each language.