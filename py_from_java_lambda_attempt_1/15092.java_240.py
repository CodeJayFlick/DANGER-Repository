Here is the translation of the given Java code into Python:

```Python
import unittest
from unittest.mock import patch

class TenantTest(unittest.TestCase):

    @patch('com.iluwatar.throttling.Tenant')
    def test_constructor(self, mock_tenant):
        with self.assertRaises(ValueError):
            tenant = mock_tenant("FailTenant", -1, None)
```

Note that Python does not have a direct equivalent to Java's `@Test` annotation. Instead, we use the built-in `unittest` module and its `TestCase` class to define test cases.

Also note that in this translation, I used the `patch` decorator from the `mock` library (which is part of the `unittest` package) to mock out the `Tenant` class for testing purposes. This allows us to isolate the code under test and verify that it raises a `ValueError` when passed invalid parameters.

Finally, note that Python's exception handling syntax (`try/except`) is different from Java's (using `assertThrows`). In this translation, we use the `with self.assertRaises()` context manager to assert that the code under test will raise a specific type of exception.