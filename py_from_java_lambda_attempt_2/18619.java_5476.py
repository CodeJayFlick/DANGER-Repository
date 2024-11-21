Here is the translation of the given Java code into equivalent Python:

```Python
import unittest
from http.cookies import SimpleCookie
from urllib.parse import urlparse

class HelloWorldSparkTest(unittest.TestCase):

    CUSTOM_HEADER_KEY = "X-Custom-Header"
    CUSTOM_HEADER_VALUE = "My Header Value"

    BODY_TEXT_RESPONSE = "Hello World"

    COOKIE_NAME = "MyCookie"
    COOKIE_VALUE = "CookieValue"
    COOKIE_DOMAIN = "mydomain.com"
    COOKIE_PATH = "/"

    READ_COOKIE_NAME = "customCookie"

    def setUp(self):
        self.handler = None
        self.is_alb = False

    def test_basic_server_handle_request_empty_filters(self):
        request = AwsProxyRequestBuilder().method("GET").path("/hello").build()
        response = self.handler.proxy(request, MockLambdaContext())
        self.assertEqual(200, response.status_code)
        self.assertTrue(CUSTOM_HEADER_KEY in response.headers)
        self.assertEqual(CUSTOM_HEADER_VALUE, response.headers[CUSTOM_HEADER_KEY])
        self.assertEqual(BODY_TEXT_RESPONSE, response.body)

    def test_add_cookie_set_cookie_on_response_valid_custom_cookie(self):
        request = AwsProxyRequestBuilder().method("GET").path("/cookie").build()
        response = self.handler.proxy(request, MockLambdaContext())
        self.assertEqual(200, response.status_code)
        self.assertTrue(HttpHeaders.SET_COOKIE in response.headers)
        cookie_value = response.headers[HttpHeaders.SET_COOKIE]
        self.assertIn(COOKIE_NAME + "=" + COOKIE_VALUE, cookie_value)
        self.assertIn(COOKIE_DOMAIN, cookie_value)
        self.assertIn(COOKIE_PATH, cookie_value)

    def test_multi_cookie_set_cookie_on_response_single_header_with_multiple_values(self):
        request = AwsProxyRequestBuilder().method("GET").path("/multi-cookie").build()
        response = self.handler.proxy(request, MockLambdaContext())
        self.assertEqual(200, response.status_code)
        self.assertTrue(HttpHeaders.SET_COOKIE in response.headers)

        cookie_value = response.headers[HttpHeaders.SET_COOKIE]
        cookies = SimpleCookie(cookie_value).values()

        self.assertEqual(len(cookies), 2)
        for cookie in cookies:
            if COOKIE_NAME + "=" + COOKIE_VALUE in str(cookie):
                continue
            elif COOKIE_NAME + "2=" + COOKIE_VALUE + "2" in str(cookie):
                break

    def test_root_resource_basic_request_expect_success(self):
        request = AwsProxyRequestBuilder().method("GET").path("/").build()
        response = self.handler.proxy(request, MockLambdaContext())
        self.assertEqual(200, response.status_code)
        self.assertTrue(CUSTOM_HEADER_KEY in response.headers)
        self.assertEqual(CUSTOM_HEADER_VALUE, response.headers[CUSTOM_HEADER_KEY])
        self.assertEqual(BODY_TEXT_RESPONSE, response.body)

    def test_read_cookie_custom_domain_name_expect_valid_cookie(self):
        request = AwsProxyRequestBuilder().method("GET").path("/cookie-read").cookie(READ_COOKIE_NAME, "test").build()
        response = self.handler.proxy(request, MockLambdaContext())
        self.assertEqual(response.body, "test")

if __name__ == "__main__":
    unittest.main()

class SparkLambdaContainerHandler:
    @staticmethod
    def getAwsProxyHandler():
        # implementation of the handler here

class AwsProxyRequestBuilder:
    def method(self, method):
        pass  # implement this method

    def path(self, path):
        pass  # implement this method

    def build(self):
        pass  # implement this method

    def alb(self):
        pass  # implement this method
```

Note: The above Python code is a direct translation of the given Java code. However, it may not work as expected because some parts are missing (like `AwsProxyRequest`, `MockLambdaContext` and actual implementation of handlers).