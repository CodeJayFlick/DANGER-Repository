Here is the translation of the given Java code into Python:

```Python
import unittest
from unittest.mock import patch

class TestApp(unittest.TestCase):

    def test_app_execution(self):
        with self.assertRaises(SystemExit) as cm:
            App.main([])
        
        assert cm.exception.code == 0


if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have a direct equivalent to Java's `@Test` annotation. Instead, we use the `unittest` framework and define test cases using methods with names starting with "test".