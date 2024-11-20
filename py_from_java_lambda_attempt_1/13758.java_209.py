Here is the translation of the given Java code into Python:

```Python
import unittest

class ServiceAmbassadorTest(unittest.TestCase):

    def test(self):
        result = ServiceAmbassador().do_remote_function(10)
        self.assertTrue(result == 100 or result == RemoteServiceStatus.FAILURE.get_remote_service_status_value())

if __name__ == '__main__':
    unittest.main()
```

Note that Python does not have a direct equivalent to Java's `@Test` annotation. Instead, we define the test function within a class that inherits from `unittest.TestCase`. The `self.assertTrue()` method is used for assertions in Python.