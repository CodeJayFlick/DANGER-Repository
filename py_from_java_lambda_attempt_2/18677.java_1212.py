Here is the equivalent Python code:

```Python
import unittest
from aws_lambda_proxy import LambdaHandler, MockLambdaContext
from aws_proxy_request_builder import AwsProxyRequestBuilder
from message_controller import MessageController
from message_data import MessageData

class WebFluxAppTest(unittest.TestCase):

    def setUp(self):
        self.handler = LambdaHandler()
        self.lambda_context = MockLambdaContext()

    @unittest.parametrize("req_type", ["API_GW", "ALB", "HTTP_API"])
    def test_hello_request_responds_with_single_message(self, req_type):
        request_builder = AwsProxyRequestBuilder("/single", "GET")
        response = self.handler.handle_request(request_builder, self.lambda_context)
        print(response.body)
        self.assertEqual(MessageController.MESSAGE, response.body)

    @unittest.parametrize("req_type", ["API_GW", "ALB", "HTTP_API"])
    def test_hello_double_request_responds_with_double_message(self, req_type):
        request_builder = AwsProxyRequestBuilder("/double", "GET")
        response = self.handler.handle_request(request_builder, self.lambda_context)
        self.assertEqual(MessageController.MESSAGE + MessageController.MESSAGE, response.body)

    @unittest.parametrize("req_type", ["API_GW", "ALB", "HTTP_API"])
    def test_message_object_parses_object_returns_correct_message(self, req_type):
        request_builder = AwsProxyRequestBuilder("/message", "POST")
        request_builder.json().body(MessageData("test message"))
        response = self.handler.handle_request(request_builder, self.lambda_context)
        self.assertIsNotNone(response)
        self.assertEqual(200, response.status_code)
        self.assertEqual("test message", response.body)

if __name__ == "__main__":
    unittest.main()
```

Note: This Python code is equivalent to the Java code provided. However, it does not include all the imports and classes as they are specific to AWS Lambda Proxy and may require additional setup or configuration in a real-world scenario.