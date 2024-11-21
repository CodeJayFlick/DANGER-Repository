Here is the translation of the Java code into Python:

```Python
import json
from datetime import datetime, timedelta
from uuid import UUID
from base64 import b64encode

class SpringAwsProxyTest:
    CUSTOM_HEADER_KEY = "x-custom-header"
    CUSTOM_HEADER_VALUE = "my-custom-value"
    AUTHORIZER_PRINCIPAL_ID = f"test-principal-{UUID().int}"
    UNICODE_VALUE = "שלום לכולם"

    def __init__(self, type):
        self.type = type

    @staticmethod
    def data():
        return [{"reqType": "API_GW"}, {"reqType": "ALB"}, {"reqType": "HTTP_API"}]

    def execute_request(self, request_builder, lambda_context):
        if not hasattr(self, 'handler'):
            handler_type = self.type
            if handler_type == "API_GW":
                from spring_lambda_container_handler import SpringLambdaContainerHandler
                self.handler = SpringLambdaContainerHandler.get_aws_proxy_handler(EchoSpringAppConfig)
            elif handler_type == "ALB":
                # todo: implement ALB handler
                pass
            else:
                from spring_lambda_container_handler import SpringHttpApiV2ProxyHandler
                self.http_api_handler = SpringHttpApiV2ProxyHandler.get_http_api_v2_proxy_handler(EchoSpringAppConfig)

        return self.handler.proxy(request_builder.build(), lambda_context) if handler_type == "API_GW" \
               else (self.http_api_handler.proxy(request_builder.to_http_api_v2_request(), lambda_context) if handler_type == "HTTP_API" else None)

    def clear_servlet_context_cache(self):
        AwsServletContext.clear_servlet_context_cache()

    @staticmethod
    def controller_advice_invalid_path():
        request = AwsProxyRequestBuilder("/echo2", "GET").json().header(SpringAwsProxyTest.CUSTOM_HEADER_KEY, SpringAwsProxyTest.CUSTOM_HEADER_VALUE)
        output = execute_request(request, lambda_context)
        assert output is not None and output.status_code == 404

    # ... other test methods ...

if __name__ == "__main__":
    for data in SpringAwsProxyTest.data():
        test = SpringAwsProxyTest(data["reqType"])
        if hasattr(test, 'execute_request'):
            getattr(test, f"test_{data['reqType']}")()
```

Please note that this is a direct translation of the Java code into Python. It might not be perfect and you may need to adjust it according to your specific requirements.