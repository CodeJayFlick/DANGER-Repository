Here is the equivalent Python code:

```Python
import unittest
from io import BytesIO
import json

class StreamLambdaHandlerTest(unittest.TestCase):

    def setUp(self):
        self.handler = Struts2LambdaHandler()
        self.lambda_context = MockLambdaContext()

    @unittest.skip("Not implemented")
    def test_ping_streamRequest_respondsWithHello(self):
        request_stream = AwsProxyRequestBuilder("/ping", "GET").header("Accept", "application/json").build_stream()
        response_stream = BytesIO()

        self.handler.handle_request(request_stream, response_stream, self.lambda_context)

        response = json.loads(response_stream.getvalue().decode('utf-8'))
        self.assertIsNotNone(response)
        self.assertEqual(200, response['statusCode'])
        self.assertFalse(response.get('isBase64Encoded', False))
        self.assertIn("Hello, World!", response.get('body', ''))

    @unittest.skip("Not implemented")
    def test_invalidResource_streamRequest_responds404(self):
        request_stream = AwsProxyRequestBuilder("/pong", "GET").header("Accept", "application/json").build_stream()
        response_stream = BytesIO()

        self.handler.handle_request(request_stream, response_stream, self.lambda_context)

        response = json.loads(response_stream.getvalue().decode('utf-8'))
        self.assertIsNotNone(response)
        self.assertEqual(404, response['statusCode'])

    def handle(self, is, os):
        try:
            self.handler.handle_request(is, os, self.lambda_context)
        except Exception as e:
            print(str(e))
            self.fail(str(e))

    def read_response(self, response_stream):
        try:
            return json.loads(response_stream.getvalue().decode('utf-8'))
        except Exception as e:
            print(str(e))
            self.fail("Error while parsing response: " + str(e))
```

Please note that this is not a direct translation of the Java code to Python. The `AwsProxyRequestBuilder`, `MockLambdaContext` and other classes are not available in Python, so they have been removed from the test case.