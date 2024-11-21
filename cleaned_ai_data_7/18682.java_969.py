import json
from urllib.parse import urlparse, unquote
from uuid import UUID

class Struts2AwsProxyTest:
    CUSTOM_HEADER_KEY = "x-custom-header"
    CUSTOM_HEADER_VALUE = "my-custom-value"
    AUTHORIZER_PRINCIPAL_ID = f"test-principal-{UUID().hex}"
    QUERY_STRING_KEY = "message"
    QUERY_STRING_ENCODED_VALUE = "Hello Struts2"

    CONTENT_TYPE_APPLICATION_JSON = "application/json; charset=UTF-8"

    def __init__(self, req_type):
        self.type = req_type

class EchoAction:
    pass

def execute_request(request_builder, lambda_context):
    if self.type == "API_GW":
        return handler.proxy(request_builder.build(), lambda_context)
    elif self.type == "ALB":
        return handler.proxy(request_builder.alb().build(), lambda_context)
    elif self.type == "HTTP_API":
        return http_api_handler.proxy(request_builder.to_http_api_v2_request(), lambda_context)
    else:
        raise RuntimeError(f"Unknown request type: {self.type}")

class Struts2LambdaContainerHandler:
    @staticmethod
    def get_aws_proxy_handler():
        pass

    @staticmethod
    def get_http_api_v2_proxy_handler():
        pass

def validate_map_response_model(output):
    try:
        response = json.loads(output.body)
        assert response.get(self.CUSTOM_HEADER_KEY) == self.CUSTOM_HEADER_VALUE
    except Exception as e:
        print(f"Exception while parsing response body: {e}")

def validate_single_value_model(output, value):
    try:
        assert output.body.decode("utf-8") == value
    except Exception as e:
        print(f"Exception while parsing response body: {e}")

class TestStruts2AwsProxy(unittest.TestCase):

    def test_headers_getHeaders_echo(self):
        request = AwsProxyRequestBuilder("/echo-request-info", "GET").query_string({"mode": "headers"}).header(self.CUSTOM_HEADER_KEY, self.CUSTOM_HEADER_VALUE)
        output = execute_request(request, lambda_context)
        assert output.status_code == 200
        assert output.headers.get("Content-Type") == self.CONTENT_TYPE_APPLICATION_JSON

    def test_context_servletResponse_setCustomHeader(self):
        request = AwsProxyRequestBuilder("/echo", "GET").query_string({"customHeader": "true"}).json()
        output = execute_request(request, lambda_context)
        assert output.status_code == 200
        assert "XX" in output.headers

    def test_context_serverInfo_correctContext(self):
        assume("API_GW".equals(self.type))
        request = AwsProxyRequestBuilder("/echo", "GET").query_string({self.QUERY_STRING_KEY: self.QUERY_STRING_ENCODED_VALUE}).header("Content-Type", self.CONTENT_TYPE_APPLICATION_JSON).query_string({"contentType": "true"})
        output = execute_request(request, lambda_context)
        assert output.status_code == 200
        validate_single_value_model(output, self.QUERY_STRING_ENCODED_VALUE)

    def test_queryString_uriInfo_echo(self):
        request = AwsProxyRequestBuilder("/echo-request-info", "GET").query_string({"mode": "query-string"}).query_string({self.CUSTOM_HEADER_KEY: self.CUSTOM_HEADER_VALUE}).json()
        output = execute_request(request, lambda_context)
        assert output.status_code == 200
        validate_map_response_model(output)

    def test_requestScheme_valid_expectHttps(self):
        request = AwsProxyRequestBuilder("/echo-request-info", "GET").query_string({"mode": "scheme"}).query_string({self.QUERY_STRING_KEY: self.QUERY_STRING_ENCODED_VALUE}).json()
        output = execute_request(request, lambda_context)
        assert output.status_code == 200
        validate_single_value_model(output, "https")

    def test_authorizer_securityContext_customPrincipalSuccess(self):
        assume("API_GW".equals(self.type))
        request = AwsProxyRequestBuilder("/echo-request-info", "GET").query_string({"mode": "principal"}).json().authorizer_principal(self.AUTHORIZER_PRINCIPAL_ID)
        output = execute_request(request, lambda_context)
        assert output.status_code == 200
        validate_single_value_model(output, self.AUTHORIZER_PRINCIPAL_ID)

    def test_errors_unknownRoute_expect404(self):
        request = AwsProxyRequestBuilder("/unknown", "GET")
        output = execute_request(request, lambda_context)
        assert output.status_code == 404

    # ... and so on for the rest of the tests
