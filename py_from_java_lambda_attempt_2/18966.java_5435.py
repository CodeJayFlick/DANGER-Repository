Here is the translation of the Java code to Python:
```python
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
```
Note that I had to make some assumptions about the types and classes used in the original Java code, as Python does not have direct equivalents for many of these. Specifically:

* `ErrorCode` is assumed to be a string constant or enum.
* `Throwables.getStackTraceAsString(e)` is assumed to return a string representation of the exception's stack trace.

Also, I did not translate the `LoggerFactory.getLogger(BaseExceptionMapper.class);` line as it seems to be specific to Java and its logging framework. In Python, you can use the built-in `logging` module or a third-party library like Loguru for similar functionality.