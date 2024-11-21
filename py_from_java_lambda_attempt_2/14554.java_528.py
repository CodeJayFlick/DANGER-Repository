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

Note that this is a simplified translation, and the original Java code may have additional functionality or complexity not captured in this Python version.