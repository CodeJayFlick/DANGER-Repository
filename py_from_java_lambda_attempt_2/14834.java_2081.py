Here's a translation of your Java code into equivalent Python:

```Python
import unittest
from hamcrest import assert_that, has_item, is_

class BusinessException(Exception):
    pass


class CustomerNotFoundException(Exception):
    pass


def retry_exponential_backoff(func, max_attempts=2, initial_delay=0, ignore_exceptions=None):
    attempts = 0
    last_exception = None

    while True:
        try:
            func()
            return
        except Exception as e:
            if ignore_exceptions and isinstance(e.__class__, ignore_exceptions):
                continue
            else:
                raise e

        attempts += 1
        delay = initial_delay * (2 ** attempts)
        last_exception = e

    return


class TestRetryExponentialBackoff(unittest.TestCase):

    def test_errors(self):
        e = BusinessException("unhandled")
        retry = lambda: raise e
        retry_exponential_backoff(retry, max_attempts=2, initial_delay=0)

        self.assertIn(e, Retry().errors())

    def test_attempts(self):
        e = BusinessException("unhandled")
        retry = lambda: raise e
        retry_exponential_backoff(retry, max_attempts=2, initial_delay=0)

        self.assertEqual(Retry().attempts(), 1)

    def test_ignore(self):
        e = CustomerNotFoundException("customer not found")
        retry = lambda: raise e
        retry_exponential_backoff(retry, max_attempts=2, initial_delay=0, ignore_exceptions=CustomerNotFoundException)

        self.assertEqual(Retry().attempts(), 2)


if __name__ == '__main__':
    unittest.main()
```

This Python code defines a `retry_exponential_backoff` function that takes in a callable and some parameters to control the retry behavior. It then tests this function using three test cases, similar to your original Java code.

Note: The Hamcrest library is not directly available for Python, so I've used equivalent assertions from the unittest module instead.