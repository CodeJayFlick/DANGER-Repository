class DbgKillCommand:
    def __init__(self, manager):
        pass  # No direct equivalent in Python for constructor

    def invoke(self):
        dbgeng = self.manager.getClient()
        # NB: process the event before terminating
        self.manager.processEvent(DbgProcessExitedEvent(0))
        dbgeng.terminateCurrentProcess()
        dbgeng.detachCurrentProcess()

class DbgProcessExitedEvent:
    def __init__(self, exit_code=0):
        pass  # No direct equivalent in Python for constructor

# Assuming these classes exist and have the same functionality as their Java counterparts
from agent.dbgeng import DebugClient
from agent.dbgeng.manager import DbgManagerImpl
