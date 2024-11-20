import unittest
from aws_proxy_request import AwsProxyRequest
from aws_proxy_request_builder import AwsProxyRequestBuilder
from mock_lambda_context import MockLambdaContext
from container_config import ContainerConfig

class TestAwsHttpServletRequest(unittest.TestCase):

    def setUp(self):
        self.content_type_request = AwsProxyRequestBuilder("/test", "GET").header("Content-Type", "application/xml; charset=utf-8").build()
        self.valid_cookie_request = AwsProxyRequestBuilder("/cookie", "GET").header("Cookie", "yummy_ cookie=choco; tasty_ cookie=strawberry").build()
        self.complex_accept_header = AwsProxyRequestBuilder("/accept", "GET").header("Accept", "text/html, application/xhtml+xml, application/xml;q=0.9,*/*;q=0.8").build()
        self.query_string = AwsProxyRequestBuilder("/test", "GET").queryString("one", "two").queryString("three", "four").build()
        self.query_string_null_value = AwsProxyRequestBuilder("/test", "GET").queryString("one", "two").queryString("three", None).build()
        self.encoded_query_string = AwsProxyRequestBuilder("/test", "GET").queryString("one", "two").queryString("json", "{\"name\":\"faisal\"}").build()
        self.multiple_params = AwsProxyRequestBuilder("/test", "GET").queryString("one", "two").queryString("one", "three").queryString("json", "{\"name\":\"faisal\"}").build()

    def test_headers_parse_header_value_multi_value(self):
        request = AwsProxyHttpServletRequest(self.content_type_request, MockLambdaContext(), None, ContainerConfig.default_config())
        values = request.parse_header_value(request.get_header("Content-Type"))

        self.assertEqual(2, len(values))
        self.assertEqual("application/xml", values[0].get_value())
        self.assertIsNone(values[0].get_key())

        self.assertEqual("charset", values[1].get_key())
        self.assertEqual("utf-8", values[1].get_value())

    def test_headers_parse_header_value_valid_multiple_cookie(self):
        request = AwsProxyHttpServletRequest(self.valid_cookie_request, MockLambdaContext(), None, ContainerConfig.default_config())
        values = request.parse_header_value(request.get_header("Cookie"), ";", ",")

        self.assertEqual(2, len(values))
        self.assertEqual("yummy_ cookie", values[0].get_key())
        self.assertEqual("choco", values[0].get_value())

        self.assertEqual("tasty_ cookie", values[1].get_key())
        self.assertEqual("strawberry", values[1].get_value())

    def test_headers_parse_header_value_complex_accept(self):
        request = AwsProxyHttpServletRequest(self.complex_accept_header, MockLambdaContext(), None, ContainerConfig.default_config())
        values = request.parse_header_value(request.get_header("Accept"), ",", ";")

        self.assertEqual(4, len(values))

    def test_headers_parse_header_value_encoded_content_with_equals(self):
        context = AwsProxyHttpServletRequest(None, None, None)
        value = Base64.getUrlEncoder().encodeToString("a".encode())

        result = context.parse_header_value(value)

        self.assertGreater(len(result), 0)
        self.assertEqual("YQ==", result[0].get_value())

    def test_headers_parse_header_value_base64_encoded_cookie_value(self):
        value = Base64.getUrlEncoder().encodeToString("a".encode())
        cookie_value = "jwt=" + value + "; secondValue=second"
        request = AwsProxyRequestBuilder("/test", "GET").header("Cookie", cookie_value).build()
        context = AwsProxyHttpServletRequest(request, None, None)

        cookies = context.get_cookies()

        self.assertEqual(2, len(cookies))
        self.assertEqual("jwt", cookies[0].getName())
        self.assertEqual(value.decode(), cookies[0].getValue())

    def test_headers_parse_header_value_cookie_with_separator_in_value(self):
        cookie_value = "jwt==test; secondValue=second"
        request = AwsProxyRequestBuilder("/test", "GET").header("Cookie", cookie_value).build()
        context = AwsProxyHttpServletRequest(request, None, None)

        cookies = context.get_cookies()

        self.assertEqual(2, len(cookies))
        self.assertEqual("jwt", cookies[0].getName())
        self.assertEqual("=test", cookies[0].getValue())

    def test_headers_parse_header_value_header_with_padding_but_not_base64_encoded(self):
        context = AwsProxyHttpServletRequest(None, None, None)

        result = context.parse_header_value("hello=")

        self.assertGreater(len(result), 0)
        self.assertEqual("hello", result[0].get_key())
        self.assertIsNone(result[0].get_value())

    def test_query_string_generate_query_string_valid_query(self):
        request = AwsProxyHttpServletRequest(self.query_string, MockLambdaContext(), None, ContainerConfig.default_config())

        parsed_string = None
        try:
            parsed_string = request.generate_query_string(request.get_aws_proxy_request().get_multi_value_query_string_parameters(), True, request.config.get_uri_encoding())
        except ServletException as e:
            e.printStackTrace()
            self.fail("Could not generate query string")

        self.assertTrue(parsed_string.contains("one=two"))
        self.assertTrue(parsed_string.contains("three=four"))
        self.assertTrue(parsed_string.contains("&") and parsed_string.index("&") > 0 and parsed_string.index("&") < len(parsed_string))

    def test_query_string_generate_query_string_null_parameter_is_empty(self):
        request = AwsProxyHttpServletRequest(self.query_string_null_value, MockLambdaContext(), None, ContainerConfig.default_config())

        parsed_string = None
        try:
            parsed_string = request.generate_query_string(request.get_aws_proxy_request().get_multi_value_query_string_parameters(), True, request.config.get_uri_encoding())
        except ServletException as e:
            e.printStackTrace()
            self.fail("Could not generate query string")

        self.assertTrue(parsed_string.endswith("three="))

    def test_query_string_with_encoded_params_generate_query_string_valid_query(self):
        request = AwsProxyHttpServletRequest(self.encoded_query_string, MockLambdaContext(), None, ContainerConfig.default_config())

        parsed_string = None
        try:
            parsed_string = request.generate_query_string(request.get_aws_proxy_request().get_multi_value_query_string_parameters(), True, request.config.get_uri_encoding())
        except ServletException as e:
            e.printStackTrace()
            self.fail("Could not generate query string")

        self.assertTrue(parsed_string.contains("one=two"))
        self.assertTrue(parsed_string.contains("json=%7B%22name%22%3A%22faisal%22%7D"))
        self.assertTrue(parsed_string.contains("&") and parsed_string.index("&") > 0 and parsed_string.index("&") < len(parsed_string))

    def test_query_string_with_multiple_values_generate_query_string_valid_query(self):
        request = AwsProxyHttpServletRequest(self.multiple_params, MockLambdaContext(), None, ContainerConfig.default_config())

        parsed_string = None
        try:
            parsed_string = request.generate_query_string(request.get_aws_proxy_request().get_multi_value_query_string_parameters(), True, request.config.get_uri_encoding())
        except ServletException as e:
            e.printStackTrace()
            self.fail("Could not generate query string")

        self.assertTrue(parsed_string.contains("one=two"))
        self.assertTrue(parsed_string.contains("one=three"))
        self.assertTrue(parsed_string.contains("json=%7B%22name%22%3A%22faisal%22%7D"))
        self.assertTrue(parsed_string.contains("&") and parsed_string.index("&") > 0 and parsed_string.index("&") < len(parsed_string))

if __name__ == "__main__":
    unittest.main()
