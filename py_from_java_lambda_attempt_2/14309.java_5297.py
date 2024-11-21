Here is the translation of the Java code to Python:
```
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

import unittest

class ApplicationExceptionTest(unittest.TestCase):
    def test_cause(self):
        cause = Exception()
        self.assertEqual(cause, ApplicationException(cause).get_cause())

if __name__ == '__main__':
    unittest.main()
```
Note that I've removed the Java-specific comments and license information at the top of the file. In Python, we don't need to specify a package name or import statements for static assertions like `assertSame`. Instead, we use the built-in `unittest` module to write unit tests.

The rest of the code is straightforward: we define a test method `test_cause()` that creates an instance of `Exception`, and then asserts that the cause returned by `ApplicationException(cause).get_cause()` is equal to the original exception.