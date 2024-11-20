class DbgDebuggeeStateChangeEvent:
    def __init__(self, flags: set, argument):
        self.flags = flags
        self.argument = argument

    @property
    def get_flags(self) -> set:
        return self.flags

    @property
    def get_argument(self) -> int:
        return self.argument


# Example usage:

flags_set = {1, 2, 3}  # equivalent to BitmaskSet<ChangeDebuggeeState>
argument = 12345

event = DbgDebuggeeStateChangeEvent(flags_set, argument)

print(event.get_flags)
print(event.get_argument)
