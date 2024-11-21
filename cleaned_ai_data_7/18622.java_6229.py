import logging
from typing import TypeVar, Generic

class SpringLambdaContainerHandler(Generic[RequestType, ResponseType]):
    def __init__(self,
                 request_type_class: type(RequestType),
                 response_type_class: type(ResponseType),
                 request_reader: 'RequestReader'[RequestType],
                 response_writer: 'ResponseWriter'[ResponseType],
                 security_context_writer: 'SecurityContextWriter',
                 exception_handler: 'ExceptionHandler',
                 application_context: 'ConfigurableWebApplicationContext' = None,
                 initialization_wrapper=None):
        super().__init__(request_type_class, response_type_class)
        self.app_context = application_context
        self.set_initialization_wrapper(initialization_wrapper)

    def set_refresh_context(self, refresh: bool) -> None:
        # this.initializer.set_refresh_context(refresh_context)
        self.refresh_context = refresh

    @property
    def initialization_wrapper(self):
        return self._initialization_wrapper

    @initialization_wrapper.setter
    def initialization_wrapper(self, value):
        self._initialization_wrapper = value

    def get_container_response(self, request: 'HttpServletRequest', latch) -> 'AwsHttpServletResponse':
        return AwsHttpServletResponse(request, latch)

    def activate_spring_profiles(self, profiles: tuple[str]) -> None:
        if not self.app_context:
            raise ContainerInitializationException("Initializer is not set yet.")
        self.profiles = profiles
        self.set_servlet_context(AwsServletContext(self))
        self.app_context.register_shutdown_hook()
        self.app_context.close()
        self.initialize()

    def handle_request(self, container_request: 'HttpServletRequest', 
                       container_response: 'AwsHttpServletResponse', lambda_context) -> None:
        if self.refresh_context:
            self.app_context.refresh()
            self.refresh_context = False

        # process filters
        req_servlet = (self.get_servlet_context()).get_servlet_for_path(container_request.path_info)
        do_filter(container_request, container_response, req_servlet)

    def initialize(self) -> None:
        if self.profiles is not None:
            self.app_context.environment.set_active_profiles(self.profiles)
        self.app_context.set_servlet_context(self.get_servlet_context())
        register_servlets()

class AwsHttpServletResponse:
    pass

class ConfigurableWebApplicationContext:
    pass

class DispatcherServlet:
    pass
