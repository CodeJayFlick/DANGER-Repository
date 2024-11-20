Here is the translation of the given Java code into equivalent Python:

```Python
class DbgRequestFocusCommand:
    def __init__(self, manager: 'DbgManagerImpl', scope: 'DbgModelTargetFocusScope', obj: 'TargetObject'):
        self.manager = manager
        self.scope = scope
        self.obj = obj

    def invoke(self):
        self.scope.do_request_focus(self.obj)
```

Note that Python does not have direct equivalent of Java's package, import statements or annotations. The above code is a straightforward translation into Python syntax and semantics.