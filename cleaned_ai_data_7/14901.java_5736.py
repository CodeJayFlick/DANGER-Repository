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
