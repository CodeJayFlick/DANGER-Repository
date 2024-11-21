class GdbCommandExitEvent:
    def __init__(self, tail):
        super().__init__(tail)

    @property
    def new_state(self) -> 'GdbState':
        return GdbState.EXIT


# Define a class for Gdb State
class GdbState:
    EXIT = "EXIT"


try:
    from typing import CharSequence  # Python 3.9+
except ImportError:
    pass

if __name__ == "__main__":
    try:
        tail = "some_tail"
        event = GdbCommandExitEvent(tail)
        print(event.new_state)  # prints: EXIT
    except Exception as e:
        print(f"An error occurred: {e}")
