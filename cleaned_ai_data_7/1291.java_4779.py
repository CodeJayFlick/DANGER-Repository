class GdbDebugOutputEvent:
    def __init__(self, tail):
        super().__init__(tail)

# This line imports a custom exception class from another module.
from agent.gdb.manager.parsing import GdbParseError

class AbstractGdbOutputEvent:  # No implementation provided in the Java code
    pass


if __name__ == "__main__":
    try:
        event = GdbDebugOutputEvent("some_tail")
    except GdbParseError as e:
        print(f"An error occurred while parsing the tail: {e}")
