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
