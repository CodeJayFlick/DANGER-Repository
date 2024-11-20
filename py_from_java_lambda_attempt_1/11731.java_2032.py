Here is the translation of the Java code to Python:
```
class ContextChange:
    def __init__(self):
        pass

    def validate(self):
        raise NotImplementedError("Abstract method must be implemented")

    def save_xml(self, s):
        raise NotImplementedError("Abstract method must be implemented")

    def restore_xml(self, el, trans):
        raise NotImplementedError("Abstract method must be implemented")

    def apply(self, pos):
        raise NotImplementedError("Abstract method must be implemented")

    def dispose(self):
        pass
```
Note that I've kept the same class and method names as in the original Java code. In Python, we don't need to specify access modifiers (public/private) or implement abstract methods explicitly like we do in Java with `abstract` keywords.

Also, since Python is dynamically typed, there's no equivalent of Java's type system for variables and method parameters.