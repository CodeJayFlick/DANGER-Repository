Here is the translation of the Java code to Python:

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

Note that the `assertDoesNotThrow` function is not directly translatable to Python, so I used a try-except block instead. The test case will fail if an exception occurs when calling the `App.main([])` method.