Here is the translation of the given Java code into Python:

```Python
import unittest
from ghidra.pcode.floatformat import FloatFormatFactory, BigFloat, BigInfinityEncoding, BigZeroEncoding

class OpBehaviorFloatLessEqualTest(unittest.TestCase):

    def testEvaluateBinaryLong(self):
        op = OpBehaviorFloatLessEqual()
        ff = FloatFormatFactory.getFloatFormat(8)

        self.assertEqual(op.evaluate_binary(8, 8, ff.get_encoding(1.234), ff.get_encoding(1.234)), 1)
        self.assertEqual(op.evaluate_binary(8, 8, ff.get_encoding(-1.234), ff.get_encoding(-1.234)), 1)
        self.assertEqual(op.evaluate_binary(8, 8, ff.get_encoding(1.234), ff.get_encoding(-1.234)), 0)
        self.assertEqual(op.evaluate_binary(8, 8, ff.get_encoding(0), ff.get_encoding(-1.234)), 0)

        self.assertEqual(op.evaluate_binary(8, 8, ff.get_encoding(0), ff.get_encoding(1.234)), 1)
        self.assertEqual(op.evaluate_binary(8, 8, ff.get_encoding(-1.234), ff.get_encoding(1.234)), 1)

        self.assertEqual(op.evaluate_binary(8, 8, ff.get_encoding(float('inf')), ff.get_encoding(1.234)), 0)
        self.assertEqual(op.evaluate_binary(8, 8, ff.get_encoding(-float('inf')), ff.get_encoding(1.234)), 1)
        self.assertEqual(op.evaluate_binary(8, 8, ff.get_encoding(1.234), ff.get_encoding(float('inf'))), 1)
        self.assertEqual(op.evaluate_binary(8, 8, ff.get_encoding(1.234), ff.get_encoding(-float('inf'))), 0)

    def testEvaluateBinaryBigInteger(self):
        op = OpBehaviorFloatLessEqual()
        ff = FloatFormatFactory.getFloatFormat(8)

        a = BigFloat(ff, 1.234)
        b = BigFloat(ff, -1.234)

        self.assertEqual(op.evaluate_binary(8, 8, ff.get_encoding(a), ff.get_encoding(a)), 1)
        self.assertEqual(op.evaluate_binary(8, 8, ff.get_encoding(b), ff.get_encoding(b)), 1)

        self.assertEqual(op.evaluate_binary(8, 8, ff.get_encoding(a), ff.get_encoding(b)), 0)
        self.assertEqual(op.evaluate_binary(8, 8, BigZeroEncoding(ff).get_encoding(), ff.get_encoding(b)), 0)

        self.assertEqual(op.evaluate_binary(8, 8, BigZeroEncoding(ff).get_encoding(), ff.get_encoding(a)), 1)
        self.assertEqual(op.evaluate_binary(8, 8, ff.get_encoding(b), ff.get_encoding(a)), 1)

        self.assertEqual(op.evaluate_binary(8, 8, BigInfinityEncoding(True, ff).get_encoding(), ff.get_encoding(a)), 0)
        self.assertEqual(op.evaluate_binary(8, 8, BigInfinityEncoding(False, ff).get_encoding(), ff.get_encoding(a)), 1)
        self.assertEqual(op.evaluate_binary(8, 8, ff.get_encoding(a), BigInfinityEncoding(True, ff).get_encoding()), 1)
        self.assertEqual(op.evaluate_binary(8, 8, ff.get_encoding(a), BigInfinityEncoding(False, ff).get_encoding()), 0)

        self.assertEqual(op.evaluate_binary(8, 8, BigInfinityEncoding(True, ff).get_encoding(), BigInfinityEncoding(True, ff).get_encoding()), 1)
        self.assertEqual(op.evaluate_binary(8, 8, BigInfinityEncoding(False, ff).get_encoding(), BigInfinityEncoding(True, ff).get_encoding()), 1)

if __name__ == '__main__':
    unittest.main()
```

Please note that you need to have the `ghidra.pcode.floatformat` module available in your Python environment.