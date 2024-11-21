class LldbSymbolsLoadedEvent:
    def __init__(self, info):
        self.info = info


# Note: In Python, we don't have a direct equivalent to Java's abstract classes.
# We can use inheritance and polymorphism instead. For example,
class AbstractLldbEvent:
    pass

class DebugEventInfo:
    pass
