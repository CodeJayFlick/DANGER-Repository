from typing import Optional

class NessieError:
    def __init__(self):
        pass

    @property
    def status(self) -> int:
        raise NotImplementedError("status must be implemented")

    @property
    def reason(self) -> str:
        raise NotImplementedError("reason must be implemented")

    @property
    def message(self) -> str:
        return self.reason

    @property
    def error_code(self) -> 'ErrorCode':
        from your_module import ErrorCode  # replace with the actual module name
        return ErrorCode.UNKNOWN

    @property
    def server_stack_trace(self) -> Optional[str]:
        raise NotImplementedError("server_stack_trace must be implemented")

    @property
    def client_processing_exception(self) -> Optional[Exception]:
        raise NotImplementedError("client_processing_exception must be implemented")

    @property
    def full_message(self) -> str:
        sb = StringBuilder()
        sb.append(f"{self.reason} (HTTP/{self.status})")
        sb.append(": ")
        sb.append(self.message)

        if self.server_stack_trace is not None:
            sb.append("\n").append(self.server_stack_trace)
        
        if self.client_processing_exception is not None:
            sw = StringWriter()
            self.client_processing_exception.print_stacktrace(sw)
            sb.append("\n").append(sw.getvalue())

        return str(sb)


class ErrorCode:
    UNKNOWN = "unknown"
