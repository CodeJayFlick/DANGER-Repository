import io

class ConsoleWriter(io.TextIOBase):
    def __init__(self, console_service, error=False):
        self.console = console_service
        self.error = error

    def close(self):
        self.console.clear_messages()

    def flush(self):
        pass  # equivalent to Java's empty implementation

    def write(self, cbuf: bytes, off: int, len: int) -> None:
        str_ = cbuf[off:off+len].decode('utf-8')
        if self.error:
            self.console.print_error(str_)
        else:
            self.console.print(str_)
