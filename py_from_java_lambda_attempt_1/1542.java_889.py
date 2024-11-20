Here is the translation of the given Java code into equivalent Python:

```Python
class LldbDestroyCommand:
    def __init__(self, manager):
        pass  # No direct equivalent in Python for constructor-like method.

    def invoke(self):
        client = self.manager.getClient()
        # NB: process the event before terminating
        self.manager.processEvent(LlldbProcessExitedEvent(0))
        client.terminateCurrentProcess()  # Note that detach is not implemented here.
```

Note:

- The Java code uses a package structure which Python does not have. So, we do not need to import anything explicitly.

- In the `__init__` method of the class in Java, there's no direct equivalent in Python for constructor-like methods (like `super(manager)`). Instead, you can define an initializer function or use default values when defining instance variables.

- The `LldbProcessExitedEvent(0)` is a custom event object which does not have any direct translation to Python. You would need to create your own class for this in Python if needed.

- In the Java code, there's no equivalent of static imports like `import agent.lldb.lldb.DebugClient;` and similar ones because Python doesn't support static imports directly.