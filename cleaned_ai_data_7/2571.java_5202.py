class TraceStack:
    def __init__(self):
        pass

    def get_thread(self):
        # Implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def get_snap(self):
        # Implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def get_depth(self):
        # Implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def set_depth(self, depth: int, at_inner: bool) -> None:
        # Implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def get_frame(self, level: int, ensure_depth: bool = False) -> 'TraceStackFrame':
        # Implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def get_frames(self) -> list:
        # Implement this method in your subclass
        raise NotImplementedError("Method not implemented")

    def delete(self):
        pass

class TraceStackFrame:
    pass
