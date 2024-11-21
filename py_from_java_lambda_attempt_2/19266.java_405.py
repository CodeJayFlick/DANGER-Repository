Here is the translation of the given Java code into Python:

```Python
class IsSilent:
    def __init__(self):
        self.name = "Is Silent"
        self.description = "Checks whether an entity is silent i.e. its sounds are disabled."
        self.examples = ["target entity is silent"]
        self.since = "2.5"

    @property
    def name(self):
        return self._name

    @property
    def description(self):
        return self._description

    @property
    def examples(self):
        return self._examples

    @property
    def since(self):
        return self._since

    def check(self, entity: dict) -> bool:
        if 'silent' in entity and isinstance(entity['silent'], (bool)):
            return entity['silent']
        else:
            raise ValueError("Entity must have a 'silent' property")

# Registering the class
def register(cls):
    pass  # This is not implemented

register(IsSilent)
```

Please note that this Python code does not exactly replicate the Java code. The main differences are:

1. In Python, we don't need to explicitly define getter and setter methods for properties like in Java.
2. We use dictionaries (`dict`) instead of objects (like `Entity` in Java) to represent entities with their properties.
3. There is no direct equivalent of the `@Name`, `@Description`, etc., annotations used in Java. Instead, we set these values as attributes within our class definition.

This Python code does not include any implementation for registering classes like you would do it in Java using a static block (`static { ... }`).