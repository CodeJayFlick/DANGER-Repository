Here is the translation of the Java code into Python:

```Python
import unittest
from aws_proxy_request import AwsProxyRequestBuilder
from lambda_handler import LambdaHandler
from mock_lambda_context import MockLambdaContext
from message_controller import MessageController

class ServletAppTest(unittest.TestCase):

    def setUp(self):
        self.handler = LambdaHandler()
        self.lambda_context = MockLambdaContext()

    @parameterized.expand(["API_GW", "ALB", "HTTP_API"])
    def test_hello_request_responds_with_single_message(self, req_type):
        aws_proxy_request_builder = AwsProxyRequestBuilder("/hello", "GET")
        aws_proxy_response = self.handler.handle_request(aws_proxy_request_builder.build(), self.lambda_context)
        self.assertEqual(MessageController.HELLO_MESSAGE, aws_proxy_response.body)

    @parameterized.expand(["API_GW", "ALB", "HTTP_API"])
    def test_validate_request_invalid_data_responds_with_400(self, req_type):
        user_data = {"firstName": "Test", "lastName": "Test", "email": "Test"}
        aws_proxy_request_builder = AwsProxyRequestBuilder("/validate", "POST")
        .header("Accept", "text/plain")
        .header("Content-Type", "application/json")
        .body(user_data)
        aws_proxy_response = self.handler.handle_request(aws_proxy_request_builder.build(), self.lambda_context)
        self.assertEqual("3", aws_proxy_response.body)

    @parameterized.expand(["API_GW", "ALB", "HTTP_API"])
    def test_message_object_parses_object_returns_correct_message(self, req_type):
        aws_proxy_request_builder = AwsProxyRequestBuilder("/message", "POST")
        .json()
        .body({"test message": None})
        aws_proxy_response = self.handler.handle_request(aws_proxy_request_builder.build(), self.lambda_context)
        self.assertEqual("test message", aws_proxy_response.body)

    @parameterized.expand(["API_GW", "ALB", "HTTP_API"])
    def test_message_object_properties_in_content_type_returns_correct_message(self, req_type):
        aws_proxy_request_builder = AwsProxyRequestBuilder("/message", "POST")
        .header("Content-Type", "application/json;v=1")
        .header("Accept", "application/json;v=1")
        .body({"test message": None})
        aws_proxy_response = self.handler.handle_request(aws_proxy_request_builder.build(), self.lambda_context)
        self.assertEqual("test message", aws_proxy_response.body)

    @parameterized.expand(["API_GW", "ALB", "HTTP_API"])
    def test_echo_message_file_name_like_parameter_returns_message(self, req_type):
        aws_proxy_request_builder = AwsProxyRequestBuilder("/echo/test.test.test", "GET")
        aws_proxy_response = self.handler.handle_request(aws_proxy_request_builder.build(), self.lambda_context)
        self.assertEqual("test.test.test", aws_proxy_response.body)

    @parameterized.expand(["API_GW", "ALB", "HTTP_API"])
    def test_get_utf8_string_returns_valid_utf8_string(self, req_type):
        lambda_container_handler = LambdaContainerHandler()
        aws_proxy_request_builder = AwsProxyRequestBuilder("/content-type/utf8", "GET")
        .header("Accept", "text/plain")
        aws_proxy_response = self.handler.handle_request(aws_proxy_request_builder.build(), self.lambda_context)
        self.assertEqual(MessageController.UTF8_RESPONSE, aws_proxy_response.body)

    @parameterized.expand(["API_GW", "ALB", "HTTP_API"])
    def test_get_utf8_json_returns_valid_utf8_string(self, req_type):
        lambda_container_handler = LambdaContainerHandler()
        aws_proxy_request_builder = AwsProxyRequestBuilder("/content-type/jsonutf8", "GET")
        aws_proxy_response = self.handler.handle_request(aws_proxy_request_builder.build(), self.lambda_context)
        self.assertEqual("{\"s\":\"" + MessageController.UTF8_RESPONSE + "\"}", aws_proxy_response.body)

    @parameterized.expand(["API_GW", "ALB", "HTTP_API"])
    def test_stream_get_utf8_string_returns_valid_utf8_string(self, req_type):
        lambda_container_handler = LambdaContainerHandler()
        stream_handler = LambdaStreamHandler(req_type)
        aws_proxy_request_builder = AwsProxyRequestBuilder("/content-type/utf8", "GET")
        .header("Accept", "text/plain")
        request_stream = None
        if req_type == "ALB":
            request_stream = aws_proxy_request_builder.alb().build_stream()
        elif req_type == "API_GW":
            request_stream = aws_proxy_request_builder.build_stream()
        else:
            request_stream = aws_proxy_request_builder.to_http_api_v2_request_stream()

        out = ByteArrayOutputStream()
        stream_handler.handle_request(request_stream, out, self.lambda_context)
        aws_proxy_response = lambda_container_handler.get_object_mapper().read_value(out.toByteArray(), AwsProxyResponse.class)
        self.assertEqual(MessageController.UTF8_RESPONSE, aws_proxy_response.body)

    @parameterized.expand(["API_GW", "ALB", "HTTP_API"])
    def test_stream_get_utf8_json_returns_valid_utf8_string(self, req_type):
        lambda_container_handler = LambdaContainerHandler()
        stream_handler = LambdaStreamHandler(req_type)
        aws_proxy_request_builder = AwsProxyRequestBuilder("/content-type/jsonutf8", "GET")
        request_stream = None
        if req_type == "ALB":
            request_stream = aws_proxy_request_builder.alb().build_stream()
        elif req_type == "API_GW":
            request_stream = aws_proxy_request_builder.build_stream()
        else:
            request_stream = aws_proxy_request_builder.to_http_api_v2_request_stream()

        out = ByteArrayOutputStream()
        stream_handler.handle_request(request_stream, out, self.lambda_context)
        aws_proxy_response = lambda_container_handler.get_object_mapper().read_value(out.toByteArray(), AwsProxyResponse.class)
        self.assertEqual("{\"s\":\"" + MessageController.UTF8_RESPONSE + "\"}", aws_proxy_response.body)

    @parameterized.expand(["API_GW", "ALB", "HTTP_API"])
    def test_spring_exception_mapping_throw404_ex_expect_mapped_to_404(self, req_type):
        aws_proxy_request_builder = AwsProxyRequestBuilder("/ex/customstatus", "GET")
        aws_proxy_response = self.handler.handle_request(aws_proxy_request_builder.build(), self.lambda_context)
        self.assertEqual(404, aws_proxy_response.status_code)

    @parameterized.expand(["API_GW", "ALB", "HTTP_API"])
    def test_echo_message_populates_single_value_headers_for_http_api_v2(self, req_type):
        if req_type == "HTTP_API":
            aws_proxy_request_builder = AwsProxyRequestBuilder("/message", "POST")
            .header("Content-Type", "application/json;v=1")
            .header("Accept", "application/json;v=1")
            .body({"test message": None})
            aws_proxy_response = self.handler.handle_request(aws_proxy_request_builder.build(), self.lambda_context)
            self.assertIsNotNone(aws_proxy_response.headers)

if __name__ == "__main__":
    unittest.main()
```

Note: This Python code is not exactly the same as the Java code. It's a translation of the logic into Python, but it may not be identical due to differences in syntax and semantics between the two languages.