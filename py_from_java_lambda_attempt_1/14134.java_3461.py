Here is the translation of the Java code to Python:
```
import unittest

class TestApp(unittest.TestCase):
    def test_should_execute_application_without_exception(self):
        try:
            App.main([])
        except Exception as e:
            self.fail(f"Exception occurred: {e}")

if __name__ == '__main__':
    unittest.main()
```
Note that I've used the `unittest` module to write a Python unit test, which is similar in spirit to the Java JUnit test. The main differences are:

* In Python, we don't need to specify a package name or import statements for the testing framework.
* We use the `try`-`except` block to catch any exceptions that might be raised by calling the `App.main([])` method.
* We use the `self.fail()` method to indicate that an exception occurred and fail the test.

I hope this helps! Let me know if you have any questions.