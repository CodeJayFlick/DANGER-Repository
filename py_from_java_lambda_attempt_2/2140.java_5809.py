Here's your Java class translated into a Python equivalent:

```Python
class DebuggerAbnormalModelClosedReason:
    def __init__(self, exc):
        self.exc = exc

    def has_exception(self):
        return True

    def is_client_initiated(self):
        return False

    def get_exception(self):
        return self.exc
```

Note that Python does not have direct equivalents for Java's `final` keyword or the concept of overriding methods. The equivalent in Python would be to define a class with an initializer (`__init__`) and then use those attributes directly without any need for explicit getter/setter methods like we do in Java.