Here is the translation of the Java code to Python:

```Python
import unittest

class TestApp(unittest.TestCase):

    def test_should_execute_dao_without_exception(self):
        try:
            App.main([])
        except Exception as e:
            self.fail(f"An exception occurred: {e}")

if __name__ == '__main__':
    unittest.main()
```

Note that Python does not have a direct equivalent to Java's `@Test` annotation. Instead, we define test methods using the name of the method starting with "test_". The `unittest.TestCase` class provides various assertion methods like `assertEqual`, `assertTrue`, etc., which are used in these tests.