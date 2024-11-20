Here is the translation of the given Java code into equivalent Python:

```Python
class ConsoleCoarseGrainedObject:
    def __init__(self):
        self.dependent_objects = [MessageDependentObject(), SignalDependentObject()]

    def get_data(self) -> list[str]:
        return [
            dependent_object.get_data() for dependent_object in self.dependent_objects
        ]

# Helper classes
class DependentObject:
    pass

class MessageDependentObject(DependentObject):
    def get_data(self) -> str:
        # Implement your logic here to generate data for this object.
        return "Message Data"

class SignalDependentObject(DependentObject):
    def get_data(self) -> str:
        # Implement your logic here to generate data for this object.
        return "Signal Data"
```

Note that Python does not have direct equivalent of Java's `@Override` annotation. The method overriding is done by name, and the compiler will check if there are any methods with same signature in parent class.

Also note that Python has no concept of packages like Java. You can put these classes into a single file or separate files as per your requirement.