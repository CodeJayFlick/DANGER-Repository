Here is the translation of the given Java code into equivalent Python:

```Python
class LldbRequestActivationCommand:
    def __init__(self, manager, activator, obj):
        self.manager = manager
        self.activator = activator
        self.obj = obj

    def invoke(self):
        self.activator.do_request_activation(self.obj)
```

Note that Python does not have direct equivalents for Java's `package`, `import` statements or the concept of classes and methods being part of a package. Also, Python is dynamically typed so it doesn't require explicit type declarations like Java does.