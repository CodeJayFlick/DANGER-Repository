import unittest
from aws_http_api_v2_security_context_writer import AwsHttpApiV2SecurityContextWriter
from aws_proxy_request_builder import AwsProxyRequestBuilder
from http_api_v2_proxy_request import HttpApiV2ProxyRequest


class TestAwsHttpApiV2SecurityContext(unittest.TestCase):

    EMPTY_AUTH = AwsProxyRequestBuilder("/", "GET").to_http_api_v2_request()
    BASIC_AUTH = AwsProxyRequestBuilder("/", "GET").authorizer_principal("test").to_http_api_v2_request()
    JWT_AUTH = AwsProxyRequestBuilder("/", "GET") \
        .authorizer_principal("test") \
        .header("Authorization", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c") \
        .to_http_api_v2_request()

    context_writer = AwsHttpApiV2SecurityContextWriter()


    def test_get_authentication_scheme_null_auth_null_schema(self):
        ctx = self.context_writer.write_security_context(self.EMPTY_AUTH, None)
        self.assertIsNone(ctx.get_authentication_scheme())
        self.assertIsNone(ctx.get_user_principal())
        self.assertFalse(ctx.is_secure())


    def test_get_authentication_scheme_jwt_auth_correct_schema(self):
        ctx = self.context_writer.write_security_context(self.BASIC_AUTH, None)
        self.assertEqual("jwt", ctx.get_authentication_scheme())
        self.assertTrue(ctx.is_secure())
        self.assertIsNone(ctx.get_user_principal())


    def test_get_principal_parse_jwt_returns_sub(self):
        ctx = self.context_writer.write_security_context(self.JWT_AUTH, None)
        self.assertEqual("jwt", ctx.get_authentication_scheme())
        self.assertTrue(ctx.is_secure())
        self.assertEqual("1234567890", ctx.get_user_principal().get_name())

if __name__ == "__main__":
    unittest.main()
