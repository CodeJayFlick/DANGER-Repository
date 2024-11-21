import logging
from enum import Enum
from typing import TypeVar, Generic, Callable, Any

_LOGGER = logging.getLogger(__name__)

class Struts2LambdaContainerHandler(Generic[RequestType, ResponseType]):
    def __init__(self,
                 request_type_class: type[RequestType],
                 response_type_class: type[ResponseType],
                 request_reader: 'AwsProxyHttpServletRequestReader',
                 response_writer: 'AwsProxyHttpServletResponseWriter',
                 security_context_writer: 'AwsProxySecurityContextWriter',
                 exception_handler: Callable[[ResponseType], None]):
        self._initialized = False

    @staticmethod
    def get_aws_proxy_handler() -> 'Struts2LambdaContainerHandler[AwsProxyRequest, AwsProxyResponse]':
        return Struts2LambdaContainerHandler(
            request_type_class=AwsProxyRequest,
            response_type_class=AwsProxyResponse,
            request_reader=AwsProxyHttpServletRequestReader(),
            response_writer=AwsProxyHttpServletResponseWriter(),
            security_context_writer=AwsProxySecurityContextWriter(),
            exception_handler=AwsProxyExceptionHandler()
        )

    @staticmethod
    def get_http_api_v2_proxy_handler() -> 'Struts2LambdaContainerHandler[HttpApiV2ProxyRequest, AwsProxyResponse]':
        return Struts2LambdaContainerHandler(
            request_type_class=HttpApiV2ProxyRequest,
            response_type_class=AwsProxyResponse,
            request_reader=AwsHttpApiV2HttpServletRequestReader(),
            response_writer=AwsProxyHttpServletResponseWriter(True),
            security_context_writer=AwsHttpApiV2SecurityContextWriter(),
            exception_handler=AwsProxyExceptionHandler()
        )

    def get_container_response(self, http_request: 'HttpRequest', latch: Any) -> 'AwsHttpResponse':
        return AwsHttpResponse(http_request, latch)

    def handle_request(self,
                        http_request: 'HttpRequest',
                        aws_http_response: 'AwsHttpResponse',
                        lambda_context: Any):
        if not self._initialized:
            self.initialize()

        # Set the servlet context
        if isinstance(http_request, AwsHttpServletRequest):
            (http_request).set_servlet_context(self.get_servlet_context())

        self.do_filter(http_request, aws_http_response)

    def initialize(self) -> None:
        _LOGGER.info("Initialize Struts2 Lambda Application ...")
        try:
            # Initialize the startup handler
            if self.startup_handler is not None:
                self.startup_handler.on_startup(self.get_servlet_context())

            filter = StrutsPrepareAndExecuteFilter()
            filter_registration = self.get_servlet_context().add_filter(STRUTS_FILTER_NAME, filter)
            filter_registration.add_mapping_for_url_patterns(
                EnumSet.of(DispatcherType.REQUEST, DispatcherType.ASYNC, DispatcherType.INCLUDE, DispatcherType.FORWARD),
                True,
                "/*"
            )
        except Exception as e:
            raise ContainerInitializationException("Could not initialize Struts2", e)

        self._initialized = True
        _LOGGER.info("... initialize of Struts2 Lambda Application completed!")

    def get_servlet(self) -> Any:
        return None

class AwsProxyHttpServletRequestReader:
    pass

class AwsHttpApiV2HttpServletRequestReader:
    pass

class AwsProxySecurityContextWriter:
    pass

class AwsHttpApiV2SecurityContextWriter:
    pass

class AwsProxyExceptionHandler:
    pass
