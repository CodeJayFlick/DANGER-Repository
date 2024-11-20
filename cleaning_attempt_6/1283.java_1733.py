class GdbBreakpointModifiedEvent:
    def __init__(self, tail):
        self.bkpt_info = None
        super().__init__(tail)
        try:
            self.bkpt_info = parse_breakpoint(tail)
        except Exception as e:
            raise ValueError("Error parsing breakpoint") from e

    @property
    def breakpoint_info(self):
        return self.bkpt_info


def parse_breakpoint(tail):
    # Implement your logic to parse the tail and extract the breakpoint information here.
    pass  # Replace this with actual implementation.


class AbstractGdbEventWithFields:
    def __init__(self, tail):
        super().__init__()
        self.info = None
        try:
            self.info = get_info(tail)
        except Exception as e:
            raise ValueError("Error parsing info") from e

    @property
    def info(self):
        return self.info


def get_info(tail):
    # Implement your logic to parse the tail and extract the information here.
    pass  # Replace this with actual implementation.

