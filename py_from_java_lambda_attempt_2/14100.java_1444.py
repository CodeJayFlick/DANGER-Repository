Here is the translation of the Java code to Python:
```
import unittest

class TestApp(unittest.TestCase):
    def test_should_execute_application_without_exception(self):
        try:
            App.main([])
        except Exception as e:
            self.fail(f"Expected no exception, but got {e}")

if __name__ == '__main__':
    unittest.main()
```
Note that I've used the `unittest` module to write a Python unit test. The code is similar in structure and intent to the original Java code, but with some differences due to the language:

* In Python, we don't need an explicit `@Test` annotation; instead, we define a method named after the test (e.g., `test_should_execute_application_without_exception`) that contains the assertion.
* The `assertDoesNotThrow` function is not available in Python's unittest module. Instead, I've used a try-except block to catch any exceptions raised by calling `App.main([])`. If an exception is caught, we fail the test using the `self.fail()` method.

I hope this helps! Let me know if you have any questions or need further assistance.