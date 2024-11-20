class LldbDestroyCommand:
    def __init__(self, manager):
        pass  # No direct equivalent in Python for constructor-like method.

    def invoke(self):
        client = self.manager.getClient()
        # NB: process the event before terminating
        self.manager.processEvent(LlldbProcessExitedEvent(0))
        client.terminateCurrentProcess()  # Note that detach is not implemented here.
