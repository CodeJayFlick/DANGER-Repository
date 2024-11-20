class InvalidatedListener:
    def __init__(self):
        pass

    class InvalidatedInvocation:
        def __init__(self, object, branch, reason):
            self.object = object
            self.branch = branch
            self.reason = reason

        def __str__(self):
            return f"<InvalidatedInvocation '{self.object}' because '{self.reason}'>"

class DebuggerModelListener:
    pass


def invalidated(object, branch, reason):
    # record the event in some way (this is not a standard Python function)
    print(f"Object {object}, Branch {branch}, Reason: {reason}")

# This class implements both InvalidatedListener and DebuggerModelListener
class GhidraInvalidatedListener(InvalidatedListener, DebuggerModelListener):

    def invalidated(self, object, branch, reason):
        super().invalidated(object, branch, reason)
