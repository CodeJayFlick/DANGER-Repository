Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from hamcrest import assert_that, is_not_none
from mockito import mock, when


class LambdaInfoApiHandlerTest(unittest.TestCase):

    def test_handle_request_with_mock_context(self):
        lambda_info_api_handler = LambdaInfoApiHandler()
        context = mock('Context')
        when(context).get_aws_request_id().thenReturn("mock aws request id")

        self.assert_not_none(lambda_info_api_handler.handle_request(None, context))


if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `@Test` annotation. Instead, we use the built-in `unittest` module to define test cases and run them using a testing framework like Pytest or Unittest.

Also, there is no direct equivalent of Java's `when().thenReturn()` in Python. We can achieve similar functionality by mocking out the method with `mockito.when(context).get_aws_request_id().thenReturn("mock aws request id")`.