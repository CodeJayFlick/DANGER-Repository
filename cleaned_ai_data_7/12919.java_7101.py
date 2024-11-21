import unittest
from ghidra_pcode import OpBehaviorFloatNan, FloatFormatFactory, BigInteger

class TestOpBehaviorFloatNan(unittest.TestCase):

    def test_evaluate_binary_long(self):
        op = OpBehaviorFloatNan()
        ff = FloatFormatFactory.getFloatFormat(8)
        
        self.assertEqual(op.evaluate_unary(1, 8, float('nan')), 1)
        self.assertEqual(op.evaluate_unary(1, 8, 0), 0)
        self.assertEqual(op.evaluate_unary(1, 8, 1.234), 0)

    def test_evaluate_binary_big_integer(self):
        op = OpBehaviorFloatNan()
        ff = FloatFormatFactory.getFloatFormat(8)
        
        self.assertEqual(op.evaluate_unary(1, 8, False).to_python(), BigInteger('1'))
        self.assertEqual(op.evaluate_unary(1, 8, False).to_python(), BigInteger('0'))
        self.assertEqual(op.evaluate_unary(1, 8, float('nan')).to_python(), BigInteger('0'))

if __name__ == '__main__':
    unittest.main()
