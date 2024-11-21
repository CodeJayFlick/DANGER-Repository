import logging
from typing import TypeVar, Generic

class NessieError(Generic):
    def __init__(self, message: str, status: int, error_code: str, reason: str, stack_trace: str = None):
        self.message = message
        self.status = status
        self.error_code = error_code
        self.reason = reason
        self.stack_trace = stack_trace

class BaseExceptionMapper:
    def __init__(self, server_config):
        self.server_config = server_config
        self.logger = logging.getLogger(__name__)

    def build_exception_response(self, status: int, reason: str, message: str, e: Exception) -> dict:
        return self.build_exception_response(
            status,
            reason,
            message,
            e,
            self.server_config.send_stacktrace_to_client(),
            lambda response_builder: {}
        )

    def build_exception_response(self, 
                                 status: int, 
                                 reason: str, 
                                 message: str, 
                                 e: Exception, 
                                 include_exception_stack_trace: bool = False, 
                                 response_handler: callable = None) -> dict:
        stack_trace = Throwables.get_stacktrace_as_string(e) if include_exception_stack_trace else None

        error_code = ErrorCode.UNKNOWN
        if isinstance(e, BaseNessieClientServerException):
            error_code = e.get_error_code()

        error = NessieError(
            message=message,
            status=status,
            error_code=error_code,
            reason=reason,
            server_stack_trace=stack_trace
        )
        self.logger.debug("Failure on server, propagated to client. Status: {}, Reason: {}, Message: {}".format(status, reason, message), e)

        response_builder = {
            'status': status,
            'entity': error.__dict__,
            'type': 'application/json'
        }
        if response_handler:
            response_handler(response_builder)
        return response_builder
