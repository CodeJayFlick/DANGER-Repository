Here's your Java code translated into Python:

```Python
import unittest
from hamcrest import assert_that, has_item, is_

class BusinessException(Exception):
    def __init__(self, message):
        super().__init__(message)

class CustomerNotFoundException(BusinessException):
    pass


def retry(attempts=1, ignore_exceptions=None):
    for _ in range(attempts):
        try:
            yield
        except (BusinessException, Exception) as e:
            if not isinstance(e, BusinessException) or not ignore_exceptions or not isinstance(e, type(ignore_exceptions)):
                raise

class RetryTest(unittest.TestCase):

    def test_errors(self):
        e = BusinessException("unhandled")
        retry_obj = retry(attempts=2)
        with self.assertRaises(BusinessException):
            list(retry_obj)
        assert_that(list(retry_obj), has_item(e))

    def test_attempts(self):
        e = BusinessException("unhandled")
        retry_obj = retry(attempts=2)
        with self.assertRaises(BusinessException):
            list(retry_obj)
        assert_that(len(list(retry_obj)), is_(1))

    def test_ignore(self):
        e = CustomerNotFoundException("customer not found")
        retry_obj = retry(attempts=2, ignore_exceptions=CustomerNotFoundException)
        with self.assertRaises(CustomerNotFoundException):
            list(retry_obj)
        assert_that(len(list(retry_obj)), is_(2))


if __name__ == '__main__':
    unittest.main()
```

Please note that Python doesn't have a direct equivalent to Java's `@Test` annotation. Instead, we use the built-in `unittest` module and define test cases as methods of a class that inherits from `unittest.TestCase`.