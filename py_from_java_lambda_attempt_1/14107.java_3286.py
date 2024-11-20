Here is the translation of the given Java code into Python:

```Python
class Event:
    STARK_SIGHTED = ("Stark sighted",)
    WARSHIPS_APPROACHING = ("Warships approaching",)
    TRAITOR_DETECTED = ("Traitor detected",)

    def __init__(self, description):
        self.description = description

    def __str__(self):
        return self.description
```

Note that Python does not have an equivalent to Java's `@RequiredArgsConstructor` annotation. In this translation, I've used a simple class with an initializer method (`__init__`) and overridden the built-in `__str__` method for string representation of instances.