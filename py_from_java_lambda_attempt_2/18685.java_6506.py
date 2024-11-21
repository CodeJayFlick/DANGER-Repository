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
        request_stream = BytesIO(json.dumps({"path": "/ping", "httpMethod": "GET"}).encode())
        response_stream = BytesIO()

        self.handler.handle_request(request_stream, response_stream, self.lambda_context)

        response = json.loads(response_stream.getvalue().decode())

        self.assertIsNotNone(response)
        self.assertEqual(200, response["statusCode"])
        self.assertFalse(response.get("isBase64Encoded", False))
        self.assertIn("pong", response["body"])
        self.assertIn("Hello, World!", response["body"])

    def test_invalidResource_streamRequest_responds404(self):
        request_stream = BytesIO(json.dumps({"path": "/pong", "httpMethod": "GET"}).encode())
        response_stream = BytesIO()

        self.handler.handle_request(request_stream, response_stream, self.lambda_context)

        response = json.loads(response_stream.getvalue().decode())

        self.assertIsNotNone(response)
        self.assertEqual(404, response["statusCode"])

if __name__ == '__main__':
    unittest.main()
```

Note that Python does not have direct equivalent of Java's `@BeforeClass` and `@Test`. Instead, we use the `setUpClass` method to set up the test class. The actual tests are defined as methods in the test case class.

Also note that AWS Lambda Proxy is a serverless framework for building RESTful APIs on AWS Lambda. It provides features like automatic routing of HTTP requests to your Lambda functions and support for JSON payload.