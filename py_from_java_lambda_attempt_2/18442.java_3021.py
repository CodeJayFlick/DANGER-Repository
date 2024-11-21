Here is the equivalent Python code:

```Python
import unittest

class TestTsPrimitiveType:
    def test_new_get(self):
        self.assertEqual(TsInt(123), TsPrimitiveType.get_by_type(TSDataType.INT32, 123))
        self.assertEqual(123, TsPrimitiveType.get_by_type(TSDataType.INT32, 123).get_int())

        self.assertEqual(TsLong(456), TsPrimitiveType.get_by_type(TSDataType.INT64, 456))
        self.assertEqual(456, TsPrimitiveType.get_by_type(TSDataType.INT64, 456).get_long())

        self.assertAlmostEqual(123.0, TsPrimitiveType.get_by_type(TSDataType.FLOAT, 123.0).get_float())
        self.assertEqual(456, TsPrimitiveType.get_by_type(TSDataType.DOUBLE, 456.0).get_double())

        binary_value = bytes("123", 'utf-8')
        self.assertEqual(TsBinary(binary_value), TsPrimitiveType.get_by_type(TSDataType.TEXT, binary_value))
        self.assertEqual(binary_value, TsPrimitiveType.get_by_type(TSDataType.TEXT, binary_value).get_binary())

        boolean_value = True
        self.assertEqual(TsBoolean(boolean_value), TsPrimitiveType.get_by_type(TSDataType.BOOLEAN, boolean_value))
        self.assertTrue(TsPrimitiveType.get_by_type(TSDataType.BOOLEAN, boolean_value).get_boolean())


if __name__ == '__main__':
    unittest.main()
```

Note that Python does not have a direct equivalent to Java's `@Test` annotation. Instead, you would typically define test cases as methods of a class that inherits from `unittest.TestCase`.