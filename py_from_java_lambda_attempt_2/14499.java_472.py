Here is the translation of the given Java code into Python:

```Python
import unittest

class TestApp(unittest.TestCase):

    def test_app(self):
        try:
            App.main([])
        except Exception as e:
            self.fail(f"An exception occurred: {e}")

if __name__ == '__main__':
    unittest.main()
```

Note that the original Java code was using JUnit Jupiter, which is a testing framework for Java. The equivalent Python code uses the built-in `unittest` module to write unit tests.