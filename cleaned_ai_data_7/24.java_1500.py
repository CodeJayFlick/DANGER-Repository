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
