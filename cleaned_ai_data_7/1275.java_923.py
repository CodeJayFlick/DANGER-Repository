class AbstractGdbEventWithStateChange:
    def __init__(self, tail):
        self.reason = None
        super().__init__(tail)
        try:
            self.reason = GdbReason.get_reason(self.info())
        except Exception as e:
            print(f"Error parsing reason: {e}")

    @property
    def reason_(self):
        return self.reason

    def new_state(self) -> 'GdbState':
        pass  # abstract method, must be implemented by subclass


class GdbReason:
    @staticmethod
    def get_reason(tail):
        raise NotImplementedError("This function is not yet implemented")
