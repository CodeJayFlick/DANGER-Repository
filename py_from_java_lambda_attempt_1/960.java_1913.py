Here is the translation of the given Java code into equivalent Python:

```Python
# Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

class DbgModelLocalDebuggerModelFactory:
    def __init__(self):
        pass

    @property
    def brief(self):
        return "MS dbgmodel.dll (WinDbg 2) local agent via GADP/TCP"

    @property
    def html_details(self):
        return "Launch a new agent using the Microsoft Debug Model (best for WinDbg 2)."

    def get_thread_name(self):
        return "Local dbgmodel.dll Agent stdout"

    def get_server_class(self):
        from . import DbgModelGadpServer
        return DbgModelGadpServer

# ExtensionPointProperties equivalent in Python:
class ExtensionPointProperties:
    def __init__(self, priority=90):
        self.priority = priority

if __name__ == "__main__":
    factory = DbgModelLocalDebuggerModelFactory()
```

Please note that this is a direct translation of the given Java code into equivalent Python.