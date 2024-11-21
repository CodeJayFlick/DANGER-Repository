class RequestReader:
    API_GATEWAY_CONTEXT_PROPERTY = "com.amazonaws.apigateway.request.context"
    API_GATEWAY_STAGE_VARS_PROPERTY = "com.amazonaws.apigateway.stage.variables"
    ALB_CONTEXT_PROPERTY = "com.amazonaws.alb.request.context"
    API_GATEWAY_EVENT_PROPERTY = "com.amazonaws.apigateway.request"
    LAMBDA_CONTEXT_PROPERTY = "com.amazonaws.lambda.context"
    JAX_SECURITY_CONTEXT_PROPERTY = "com.amazonaws.serverless.jaxrs.securityContext"
    HTTP_API_CONTEXT_PROPERTY = "com.amazonaws.httpapi.request.context"
    HTTP_API_STAGE_VARS_PROPERTY = "com.amazonaws.httpapi.stage.variables"
    HTTP_API_EVENT_PROPERTY = "com.amazonaws.httpapi.request"

    def __init__(self):
        pass

    def read_request(self, request: dict, security_context: dict, lambda_context: dict, config: dict) -> dict:
        raise NotImplementedError("readRequest method must be implemented by subclass")

    @abstractmethod
    def get_request_class(self) -> type:
        pass


class ContainerConfig:
    def __init__(self):
        self.strip_base_path = False
        self.service_base_path = ""

    def is_strip_base_path(self):
        return self.strip_base_path

    def set_strip_base_path(self, strip_base_path: bool):
        self.strip_base_path = strip_base_path

    def get_service_base_path(self) -> str:
        return self.service_base_path

    def set_service_base_path(self, service_base_path: str):
        self.service_base_path = service_base_path


def strip_base_path(request_path: str, config: ContainerConfig) -> str:
    if not config.is_strip_base_path():
        return request_path
    if request_path.startswith(config.get_service_base_path()):
        new_request_path = request_path.replaceFirst(config.get_service_base_path(), "")
        if not new_request_path.startswith("/"):
            new_request_path += "/"
        return new_request_path
    return request_path


# Example usage:
class MyRequestReader(RequestReader):
    def read_request(self, request: dict, security_context: dict, lambda_context: dict, config: ContainerConfig) -> dict:
        # Your implementation here
        pass

    def get_request_class(self) -> type:
        return requests.MyRequestClass


config = ContainerConfig()
request_reader = MyRequestReader()

# Example usage of strip_base_path function
print(strip_base_path("/path/to/service", config))
