class Trace:
    def __init__(self):
        self.TRACE_ICON = None  # Replace with actual icon loading logic

    class TraceBookmarkChangeType:
        ADDED = object()
        CHANGED = object()
        LIFESPAN_CHANGED = object()
        DELETED = object()

    class TraceBreakpointChangeType:
        ADDED = object()
        CHANGED = object()
        LIFESPAN_CHANGED = object()
        DELETED = object()

    # ... and so on for each of the other classes

    def get_base_language(self):
        raise NotImplementedError("Must be implemented by subclass")

    def get_base_compiler_spec(self):
        raise NotImplementedError("Must be implemented by subclass")

    def get_base_address_factory(self):
        raise NotImplementedError("Must be implemented by subclass")

    # ... and so on for each of the other methods

class LockHold:
    pass
