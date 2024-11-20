Here is the translation of the Java code to Python:
```
class AbstractGdbCommandWithThreadAndFrameId(T):
    MI2_FRAME_PREFIX = " --frame "
    def __init__(self, manager: GdbManagerImpl, thread_id: int, frame_id: int) -> None:
        super().__init__(manager, thread_id)
        self.frame_id = frame_id

    def make_frame_part(self) -> str:
        return f"{MI2_FRAME_PREFIX}{frame_id}" if frame_id is not None else ""

    @property
    def frame_id(self) -> int:
        return self._frame_id

    def implies_current_frame_id(self) -> int:
        return self.frame_id

    def encode(self, thread_part: str) -> str:
        return self.encode(thread_part, self.make_frame_part())

    def encode(self, thread_part: str, frame_part: str) -> str:
        # abstract method implementation
        pass
```
Note that I've used the `T` placeholder to indicate a generic type parameter, which is not directly translatable to Python. In Python, you would typically use a specific type or None for this purpose.

Also, I've kept the `encode` method as an abstract method in Python, since it's intended to be implemented by subclasses.