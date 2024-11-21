Here is the equivalent Python code:

```Python
import unittest
from aws_lambda_proxy import handler as StreamLambdaHandler
from aws_lambda_proxy.model import AwsProxyResponse
from aws_lambda_proxy.testutils import MockLambdaContext
from io import BytesIO
import json

class TestStreamLambdaHandler(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.handler = StreamLambdaHandler()
        cls.lambda_context = MockLambdaContext()

    def test_ping_streamRequest_respondsWithHello(self):
        request_stream = self._build_request("/ping", "GET")
        response_stream = BytesIO()

        try:
            self.handler.handle_request(request_stream, response_stream, self.lambda_context)
        except Exception as e:
            print(str(e))
            self.fail("Error while handling the request: " + str(e))

        response = json.loads(response_stream.getvalue().decode('utf-8'))
        self.assertIsNotNone(response)
        self.assertEqual(200, response['statusCode'])
        self.assertFalse(response.get('isBase64Encoded', False))
        self.assertIn("pong", response['body'])
        self.assertIn("Hello, World!", response['body'])

    def test_invalidResource_streamRequest_responds404(self):
        request_stream = self._build_request("/pong", "GET")
        response_stream = BytesIO()

        try:
            self.handler.handle_request(request_stream, response_stream, self.lambda_context)
        except Exception as e:
            print(str(e))
            self.fail("Error while handling the request: " + str(e))

        response = json.loads(response_stream.getvalue().decode('utf-8'))
        self.assertIsNotNone(response)
        self.assertEqual(404, response['statusCode'])

    def _build_request(self, resource_path, http_method):
        return {
            'resourcePath': resource_path,
            'httpMethod': http_method
        }

if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `@BeforeClass` and `@Test`. Instead, we use the `setUpClass` method to set up class-level variables. The test methods are defined using the `test_` prefix as per PEP 8 conventions.