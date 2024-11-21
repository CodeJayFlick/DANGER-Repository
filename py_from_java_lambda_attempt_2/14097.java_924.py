Here is the translation of the Java code to Python:

```Python
import unittest

class TestApp(unittest.TestCase):

    def test_should_execute_application_without_exception(self):
        try:
            App.main([])
        except Exception as e:
            self.fail(f"An exception occurred: {e}")

if __name__ == '__main__':
    unittest.main()
```

Note that Python does not have a direct equivalent to Java's `@Test` annotation. Instead, we define the test function using the name of the test method (in this case, `test_should_execute_application_without_exception`). The `unittest.TestCase` class provides methods like `assertEqual`, `assertTrue`, etc., which can be used for assertions in tests.