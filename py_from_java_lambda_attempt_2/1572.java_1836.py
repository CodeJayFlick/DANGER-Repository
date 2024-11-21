Here is the translation of the given Java code into equivalent Python:

```Python
class LldbSetActiveSessionCommand:
    def __init__(self, manager, session):
        self.manager = manager
        self.session = session

    def invoke(self):
        client = self.manager.get_client()
        debugger = client.get_debugger()
        debugger.set_selected_target(self.session)
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or the concept of classes being part of a package. Also, there is no equivalent to Java's `@Override` annotation in Python.

In this translation:

- The class name and method names are similar but with different casing (Python uses lowercase letters).
- The constructor (`__init__`) initializes instance variables.
- The `invoke` method contains the same logic as its Java counterpart, using dot notation for attribute access.