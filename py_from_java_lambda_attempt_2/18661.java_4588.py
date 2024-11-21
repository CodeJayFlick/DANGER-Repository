Here is the equivalent Python code:

```Python
import unittest
from aws_lambda_proxy_handler import LambdaHandler
from mock_lambda_context import MockLambdaContext
from aws_proxy_request_builder import AwsProxyRequestBuilder
from security_config import SecurityConfig

class TestSecurityApp(unittest.TestCase):

    def setUp(self):
        self.handler = LambdaHandler()
        self.lambda_context = MockLambdaContext()

    def test_hello_request_with_auth_responds_with_single_message(self):
        req = AwsProxyRequestBuilder("/hello", "GET").build()
        resp = self.handler.handle_request(req, self.lambda_context)
        self.assertEqual(401, resp.status_code)
        self.assertTrue("WWW-Authenticate" in resp.headers)

        req = AwsProxyRequestBuilder("/hello", "GET") \
            .basic_auth(SecurityConfig.USERNAME, SecurityConfig.PASSWORD) \
            .header("Accept", "text/plain") \
            .build()
        resp = self.handler.handle_request(req, self.lambda_context)
        self.assertEqual(200, resp.status_code)

if __name__ == "__main__":
    unittest.main()
```

Note: This Python code is equivalent to the Java code provided. However, it assumes that you have a separate module for your AWS Lambda handler and another one for your security configuration. The actual implementation of these modules would depend on how they are implemented in your original Java code.

Also note that I used `unittest` framework which comes with Python's standard library.