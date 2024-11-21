import aws_lambda_runtime as lambda_runtime

class LambdaHandler:
    def __init__(self, req_type):
        self.type = req_type
        if req_type in ["API_GW", "ALB"]:
            try:
                from spring_boot_proxy import SpringBootProxyHandlerBuilder
                handler = SpringBootProxyHandlerBuilder().default_proxy() \
                    .initialization_wrapper(InitializationWrapper()) \
                    .servlet_application(ServletApplication) \
                    .springBootApplication(class=ServletApplication).build_and_initialize()
            except ContainerInitializationException as e:
                print(f"Error initializing container: {e}")
        elif req_type == "HTTP_API":
            try:
                from spring_boot_proxy import SpringBootProxyHandlerBuilder
                http_api_handler = SpringBootProxyHandlerBuilder().default_http_api_v2_proxy() \
                    .initialization_wrapper(InitializationWrapper()) \
                    .servlet_application(ServletApplication) \
                    .springBootApplication(class=ServletApplication).build_and_initialize()
            except ContainerInitializationException as e:
                print(f"Error initializing container: {e}")
        else:
            raise ValueError("Unknown request type")

    def handle_request(self, aws_proxy_request, context):
        if self.type in ["API_GW", "ALB"]:
            return handler.proxy(aws_proxy_request.build(), context)
        elif self.type == "HTTP_API":
            return http_api_handler.proxy(aws_proxy_request.to_http_api_v2_request(), context)
        else:
            raise RuntimeError(f"Unknown request type: {self.type}")
