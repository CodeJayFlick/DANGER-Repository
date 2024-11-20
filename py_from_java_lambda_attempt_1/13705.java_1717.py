Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from unittest.mock import patch

class TestApp(unittest.TestCase):

    @unittest.skipIf(sys.platform.startswith('java'), "This test should not run on a Jython environment")
    def test_app_execution(self):
        with self.assertRaises(SystemExit) as cm:
            App.main([])
        assert cm.exception.code == 0
```

Note that Python's unittest module does not have an equivalent to Java's `assertDoesNotThrow` method. Instead, we use the `with self.assertRaises()` context manager to test for exceptions.

Also note that this code assumes you are using a Python script with the same name as your App class (e.g., `app.py`).