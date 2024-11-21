Here is the translation of the given Java code into Python:

```Python
class Constraint:
    def __init__(self, name):
        self.name = name

    @property
    def name(self):
        return self._name

    def is_satisfied(self, t):
        raise NotImplementedError("Subclasses must implement this method")

    def load_constraint_data(self, data):
        raise NotImplementedError("Subclasses must implement this method")

    def __eq__(self, obj):
        if not isinstance(obj, Constraint):
            return False
        return self.name == obj.name

    def get_description(self):
        raise NotImplementedError("Subclasses must implement this method")
```

Note that I've used Python's property decorator to create a read-only `name` attribute. This is equivalent to the Java getter and setter methods for the `name` field.

I've also replaced the abstract methods with placeholder implementations (`raise NotImplementedError`) since these are not directly translatable into Python (Python does not have an abstract class concept like Java).