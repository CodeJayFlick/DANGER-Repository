Here is the translation of the given Java code into Python:

```Python
import unittest
from unittest.mock import patch

class TestApp(unittest.TestCase):

    @patch('builtins.print')
    def test_app(self, mock_print):
        try:
            App.main([])
        except Exception as e:
            self.fail(f"Expected no exception but got {e}")
        else:
            pass  # No assertion needed if the function doesn't throw an exception

if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have a direct equivalent of Java's `@Test` annotation. Instead, we use the `unittest` framework to define test cases and methods.

The original code was using JUnit Jupiter for testing in Java. In Python, we are using the built-in `unittest` module for unit tests.