class LldbModuleLoadedEvent:
    def __init__(self, info):
        self.info = info


# Note: In Python, we don't have a direct equivalent to Java's "package" declaration.
# However, it's common practice in Python to use the dot notation (e.g., agent.lldb.manager.evt) 
# when importing modules or classes from other packages.

import lldb

class DebugModuleInfo:
    pass


class AbstractLldbEvent(DebugModuleInfo):
    def __init__(self, info):
        self.info = info
