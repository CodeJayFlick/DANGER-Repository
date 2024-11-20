class TraceAddressSnapRangePropertyMap:
    def get_name(self):
        pass  # implement this method in your subclass

    def get_register_space(self, thread: 'TraceThread', create_if_absent=False) -> 'RegisterSpace':
        pass  # implement this method in your subclass

    def get_register_space(self, frame: 'StackFrame', create_if_absent=False) -> 'RegisterSpace':
        pass  # implement this method in your subclass


class RegisterSpace:
    pass


class TraceThread:
    pass


class StackFrame:
    pass
