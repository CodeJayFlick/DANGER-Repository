class DomainObjectException(Exception):
    def __init__(self, t=None):
        self.t = t
        super().__init__()

    def print_stack_trace(self):
        if self.t:
            self.t.print_stack_trace()
        else:
            super().print_stack_trace()

    def print_stack_trace_to_stream(self, stream):
        if self.t:
            self.t.print_stack_trace(stream)
        else:
            super().print_stack_trace(stream)

    def print_stack_trace_to_writer(self, writer):
        if self.t:
            self.t.print_stack_trace(writer)
        else:
            super().print_stack_trace(writer)

    def __str__(self):
        if self.t:
            return f"{type(self).__name__} caused by: {self.t}"
        return super().__str__()
