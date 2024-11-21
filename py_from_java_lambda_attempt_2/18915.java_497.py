Here is the translation of the Java code into Python:

```Python
class ResteasyExceptionMapper:
    def __init__(self):
        pass  # Unused constructor

    @staticmethod
    def build_exception_response(status_code: int, reason_phrase: str, message: str, exception: Exception, send_stack_trace: bool = False) -> dict:
        response = {
            "status": status_code,
            "reason-phrase": reason_phrase,
            "message": message,
            "exception": exception
        }
        if not send_stack_trace:
            del response["stack-trace"]
        return {"response": response}

    def to_response(self, exception: ResteasyViolationException) -> dict:
        e = exception.get_exception()
        if e is None:
            return_value_violation = not exception.get_return_value_violations().isEmpty()
            status = Status.INTERNAL_SERVER_ERROR if return_value_violation else Status.BAD_REQUEST
            message = exception.getMessage()
            response = self.build_exception_response(
                status.getStatusCode(),
                status.getReasonPhrase(),
                message,
                exception,
                False  # No need to send the stack trace for a validation error
            )
        else:
            response = self.build_exception_response(
                Status.INTERNAL_SERVER_ERROR.getStatusCode(),
                Status.INTERNAL_SERVER_ERROR.getReasonPhrase(),
                self.unwrap_exception(e),
                exception
            )

        return {"response": response}

    def unwrap_exception(self, t: Exception) -> str:
        sb = StringBuffer()
        do_unwrap_exception(sb, t)
        return sb.toString()

def do_unwrap_exception(sb: StringBuffer, t: Exception):
    if t is None:
        return

    sb.append(str(t))
    if t.getCause() and t != t.getCause():
        sb.append('[')
        do_unwrap_exception(sb, t.getCause())
        sb.append(']')
```

Note that Python does not have direct equivalents for Java's `@Inject`, `@Provider` annotations. Also, the code assumes a `ServerConfig` class which is used in the original Java code but has no equivalent in this translation.