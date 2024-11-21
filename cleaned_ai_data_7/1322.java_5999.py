import math

class GdbStackFrame:
    def __init__(self):
        self._address = None
        self._function_name = ""
        self._level = 0
        self._thread = None

    @property
    def address(self) -> int | str:  # Note the type hinting!
        return self._address

    @address.setter
    def address(self, value):
        if isinstance(value, (int, math.BigInteger)):
            self._address = value
        else:
            raise ValueError("Invalid address")

    @property
    def function_name(self) -> str | None:
        return self._function_name

    @function_name.setter
    def function_name(self, value: str):
        if isinstance(value, str):
            self._function_name = value
        else:
            raise ValueError("Invalid function name")

    @property
    def level(self) -> int:
        return self._level

    @level.setter
    def level(self, value: int):
        if isinstance(value, int):
            self._level = value
        else:
            raise ValueError("Invalid frame level")

    def set_active(self, internal: bool) -> None:
        # Note that Python doesn't have a direct equivalent to Java's CompletableFuture.
        # You may want to use the `asyncio` library or create your own asynchronous mechanism.

    @property
    def thread(self) -> object | None:
        return self._thread

    @thread.setter
    def thread(self, value: object):
        if isinstance(value, type(None)):
            self._thread = value
        else:
            raise ValueError("Invalid thread")

    def fill_with(self, other_frame: 'GdbStackFrame') -> None:
        # Note that Python doesn't have a direct equivalent to Java's null-safe method calls.
        # You may want to use the `if` statement or create your own null-safety mechanism.

# Example usage:
frame = GdbStackFrame()
print(frame.address)  # prints None
