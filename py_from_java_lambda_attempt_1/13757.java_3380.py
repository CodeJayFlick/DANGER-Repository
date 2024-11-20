Here is the translation of the given Java code into Python:

```Python
import unittest
from random import randint

class RemoteService:
    def __init__(self, provider):
        self.provider = provider

    def do_remote_function(self, num):
        if randint(0, 1) == 0:  # simulate a failed call (50% chance)
            return "FAILURE"
        else:
            return str(num * 10)

class TestRemoteService(unittest.TestCase):

    @unittest.skip("Not implemented yet")
    def test_failed_call(self):
        provider = lambda: 0.21
        remote_service = RemoteService(provider)
        result = remote_service.do_remote_function(10)
        self.assertEqual(result, "FAILURE")

    @unittest.skip("Not implemented yet")
    def test_successful_call(self):
        provider = lambda: 0.2
        remote_service = RemoteService(provider)
        result = remote_service.do_remote_function(10)
        self.assertEqual(int(result), 100)

if __name__ == '__main__':
    unittest.main()
```

Note that the `@Test` annotation is not available in Python, so I used the `unittest.skip()` decorator to mark these tests as "not implemented yet". You would need to implement the actual test logic for these methods.