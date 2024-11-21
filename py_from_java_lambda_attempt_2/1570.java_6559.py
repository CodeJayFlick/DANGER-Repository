Here is the translation of the given Java code into equivalent Python:

```Python
class LldbRequestFocusCommand:
    def __init__(self, manager, scope, obj):
        self.manager = manager
        self.scope = scope
        self.obj = obj

    def invoke(self):
        self.scope.do_request_focus(self.obj)
```

Note that this translation is a direct equivalent of the given Java code. Python does not have an exact equivalent to Java's `package`, so I did not include any package declaration in the above Python code.