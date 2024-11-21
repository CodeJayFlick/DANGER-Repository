Here is the equivalent Python code:

```
class Weekday:
    MONDAY = ("Monday",)
    TUESDAY = ("Tuesday",)
    WEDNESDAY = ("Wednesday",)
    THURSDAY = ("Thursday",)
    FRIDAY = ("Friday",)
    SATURDAY = ("Saturday",)
    SUNDAY = ("Sunday",)

    def __init__(self, description):
        self.description = description

    def __str__(self):
        return self.description
```

Note that Python does not have an equivalent to Java's `@RequiredArgsConstructor` annotation. In this translation, I've used a simple class with an initializer method (`__init__`) and overridden the built-in `__str__` method to provide a string representation of each enum value.

Also note that in Python, we don't need to declare types for variables or function parameters like we do in Java. The equivalent code is much more concise!