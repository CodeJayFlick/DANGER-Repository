import unittest
from ghidra_pcode_opbehavior import OpBehaviorFloatNotEqual, FloatFormatFactory, BigInfinityEncoding, BigNaNEncoding


class TestOpBehaviorFloatNotEqual(unittest.TestCase):

    def test_evaluate_binary_long(self):
        op = OpBehaviorFloatNotEqual()
        ff = FloatFormatFactory().get_float_format(8)

        self.assertEqual(op.evaluate_binary(1, 8, ff.get_encoding(1.234), ff.get_encoding(1.234)), 0)
        self.assertEqual(op.evaluate_binary(1, 8, ff.get_encoding(-1.234), ff.get_encoding(-1.234)), 0)
        self.assertEqual(op.evaluate_binary(1, 8, ff.get_encoding(-1.234), ff.get_encoding(1.234)), 1)
        self.assertEqual(op.evaluate_binary(1, 8, ff.get_encoding(float('inf')), ff.get_encoding(float('inf'))), 0)
        self.assertEqual(op.evaluate_binary(1, 8, ff.get_encoding(float('-inf')), ff.get_encoding(float('inf'))), 1)
        self.assertEqual(op.evaluate_binary(1, 8, ff.get_encoding(float('-inf')), ff.get_encoding(float('-inf'))), 0)
        self.assertEqual(op.evaluate_binary(1, 8, ff.get_encoding(float('inf')), ff.get_encoding(float('nan'))), 1)


    def test_evaluate_binary_big_integer(self):
        op = OpBehaviorFloatNotEqual()
        ff = FloatFormatFactory().get_float_format(8)

        a = ff.get_big_float(1.234)
        b = ff.get_big_float(-1.234)
        self.assertEqual(op.evaluate_binary(1, 8, ff.get_encoding(a), ff.get_encoding(a)), 0)
        self.assertEqual(op.evaluate_binary(1, 8, ff.get_encoding(b), ff.get_encoding(b)), 0)
        self.assertEqual(op.evaluate_binary(1, 8, ff.get_encoding(b), ff.get_encoding(a)), 1)
        self.assertEqual(op.evaluate_binary(1, 8, BigInfinityEncoding(False).get_encoding(), BigInfinityEncoding(False).get_encoding()), 0)
        self.assertEqual(op.evaluate_binary(1, 8, BigInfinityEncoding(False).get_encoding(), BigNaNEncoding().get_encoding()), 1)
        self.assertEqual(op.evaluate_binary(1, 8, BigInfinityEncoding(True).get_encoding(), BigInfinityEncoding(True).get_encoding()), 0)


if __name__ == '__main__':
    unittest.main()
