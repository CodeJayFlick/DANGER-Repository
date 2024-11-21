Here is the translation of the Java code to Python:
```
class ModelActivatedPluginEvent:
    NAME = "Model Focus"

    def __init__(self, source, model):
        super().__init__(source, self.NAME)
        self.new_model_ref = weakref.ref(model)

    @property
    def active_model(self):
        return self.new_model_ref()

# Note: In Python, we don't need to declare the type of a variable or method,
# so I removed those declarations. Also, Python doesn't have a direct equivalent
# to Java's `WeakReference` class, but we can use the `weakref` module instead.
import weakref

class PluginEvent:
    def __init__(self, source, name):
        self.source = source
        self.name = name

    # Add any other methods or properties you want here...
```
Note that I created a separate class for `PluginEvent`, as it seems to be an abstract base class in the Java code. In Python, we can simply define a new class with the same attributes and behavior.

Also, I used the `weakref` module from Python's standard library to create a weak reference to the `DebuggerObjectModel` instance, similar to how you would use `WeakReference` in Java.