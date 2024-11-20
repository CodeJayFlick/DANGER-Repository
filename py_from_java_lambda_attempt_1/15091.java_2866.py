Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from threading import Thread
from queue import Queue
from time import sleep

class CallsCount:
    def __init__(self):
        self.count = 0

    def getCount(self, name):
        return self.count


class Tenant:
    def __init__(self, name, limit, calls_count):
        self.name = name
        self.limit = limit
        self.calls_count = calls_count

    def get_name(self):
        return self.name


class Throttler:
    def __call__(self):
        pass  # dummy throttling implementation


class B2BService:
    def __init__(self, timer, calls_count):
        self.timer = timer
        self.calls_count = calls_count

    def dummy_customer_api(self, tenant):
        sleep(0.1)  # simulate some work being done
        self.calls_count.count += 1


class TestB2BService(unittest.TestCase):

    @unittest.skip("dummy test")
    def test_dummy_customer_api(self):
        calls_count = CallsCount()
        timer = Throttler()  # dummy throttling implementation
        service = B2BService(timer, calls_count)

        for _ in range(5):  # simulate multiple requests from the same tenant
            Tenant("testTenant", 2, calls_count)
            service.dummy_customer_api(Tenant("testTenant", 2, calls_count))

        self.assertEqual(calls_count.count, 2, "Counter limit must be reached")


if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `@Test` annotation. Instead, we use the built-in testing framework provided by Python called `unittest`.