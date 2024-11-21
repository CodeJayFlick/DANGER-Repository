Here is a translation of the Java code into equivalent Python:

```Python
import logging

class LambdaHandler:
    def __init__(self, req_type):
        self.type = req_type
        if req_type in ["API_GW", "ALB"]:
            try:
                from springboot_lambda_container_handler import SpringBootLambdaContainerHandler
                handler = SpringBootLambdaContainerHandler(AwsProxyRequest(), AwsProxyResponse())
                handler.initialization_wrapper(InitializationWrapper())
                handler.spring_boot_application(WebFluxTestApplication)
                handler.build_and_initialize()
            except ContainerInitializationException as e:
                logging.error(e)

        elif req_type == "HTTP_API":
            try:
                from springboot_lambda_container_handler import SpringBootLambdaContainerHandler
                http_api_handler = SpringBootLambdaContainerHandler(HttpApiV2ProxyRequest(), AwsProxyResponse())
                http_api_handler.initialization_wrapper(InitializationWrapper())
                http_api_handler.spring_boot_application(WebFluxTestApplication)
                http_api_handler.build_and_initialize()
            except ContainerInitializationException as e:
                logging.error(e)

    def handle_request(self, aws_proxy_request: 'AwsProxyRequestBuilder', context):
        if self.type in ["API_GW", "ALB"]:
            return handler.proxy(aws_proxy_request.build(), context)
        elif self.type == "HTTP_API":
            return http_api_handler.proxy(aws_proxy_request.to_http_api_v2_request(), context)
        else:
            raise RuntimeError(f"Unknown request type: {self.type}")
```

Please note that this is a translation of the Java code into Python, and it may not be exactly equivalent. The original Java code seems to use AWS Lambda specific classes and interfaces which are not available in standard Python libraries. You would need to implement these yourself or find alternative solutions if you want to run this code as-is on Python.

Also note that I have used type hints for the `handle_request` method, but it's up to you whether you actually intend to use them or just leave them there for documentation purposes.