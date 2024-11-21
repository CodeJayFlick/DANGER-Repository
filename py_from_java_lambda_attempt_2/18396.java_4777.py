Here is the equivalent Python code:

```Python
import unittest

class ExpressionTest(unittest.TestCase):

    def test_global_time(self):
        from tsfile.read.expression import GlobalTimeExpression as GTE
        from tsfile.read.filter import TimeFilter as TF

        global_time_expression = GTE(TF.eq(10))
        global_time_expression.set_filter(TF.eq(100))
        self.assertEqual(global_time_expression.get_filter(), 100)

    def test_and_binary(self):
        from tsfile.read.expression import GlobalTimeExpression as GTE
        from tsfile.read.filter import TimeFilter as TF

        left = GTE(TF.eq(1))
        right = GTE(TF.eq(2))
        binary_expression = BinaryExpression.and_(left, right)
        binary_expression.set_left(GTE(TF.eq(10)))
        binary_expression.set_right(GTE(TF.eq(20)))

    def test_or_binary(self):
        from tsfile.read.expression import GlobalTimeExpression as GTE
        from tsfile.read.filter import TimeFilter as TF

        left = GTE(TF.eq(1))
        right = GTE(TF.eq(2))
        binary_expression = BinaryExpression.or_(left, right)
        binary_expression.set_left(GTE(TF.eq(10)))
        binary_expression.set_right(GTE(TF.eq(20)))

if __name__ == '__main__':
    unittest.main()
```

Please note that this code is equivalent to the Java code provided. However, Python does not have a direct equivalent of JUnit's `@Test` annotation or its assertion methods like `assertEquals`. Instead, we use Python's built-in unit testing framework and write test cases as separate functions in our class.