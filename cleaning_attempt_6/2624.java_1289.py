class TraceSnap:
    def __init__(self):
        pass

    def get_trace(self) -> 'Trace':
        raise NotImplementedError("Subclasses must implement this method")

    def get_snap(self) -> int:
        raise NotImplementedError("Subclasses must implement this method")
