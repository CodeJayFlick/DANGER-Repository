Here is the translation of the given Java code into Python:

```Python
import unittest
from unittest.mock import patch

class TestApp(unittest.TestCase):

    def test_should_execute_application_without_exception(self):
        with self.assertRaises(SystemExit) as cm:
            App.main([])
        
        assert cm.exception.code == 0


if __name__ == '__main__':
    unittest.main()
```

Please note that Python's `unittest` module does not have a direct equivalent to Java's JUnit. The above code uses the built-in `unittest` module and its assertions for testing purposes.