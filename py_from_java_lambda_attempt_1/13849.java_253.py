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

Note that this is a simple translation, and the original Java code was likely part of a larger project. The Python version may not be identical to the original due to differences in syntax and structure between the two languages.