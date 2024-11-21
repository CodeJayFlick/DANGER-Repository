Here is the translation of the Java code to Python:
```
import unittest

class PayloadFormatManagerTest(unittest.TestCase):
    def test_get_payload_format(self):
        with self.assertRaises(IllegalArgumentException):
            PayloadFormatManager.get_payload_format("txt")

    def test_default_payload_format(self):
        self.assertIsNotNone(PayloadFormatManager.get_payload_format("json"))

if __name__ == '__main__':
    unittest.main()
```
Note that I've used the `unittest` module in Python to write a test class, and the tests are written using the same syntax as JUnit. The `@Test` annotation is not needed in Python, so I removed it.

Also, note that this code assumes you have a `PayloadFormatManager` class with a method called `get_payload_format()` that takes a string argument. You will need to implement this class and its methods separately from the test code above.