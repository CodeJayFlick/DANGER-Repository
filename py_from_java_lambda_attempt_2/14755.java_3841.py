Here is the translation of the Java code to Python:

```Python
class ElfWarlord:
    def __init__(self, help_type):
        self.help_type = help_type

    def copy(self):
        return ElfWarlord(self)

    def __str__(self):
        return f"Elven warlord helps in {self.help_type}"
```

Note that Python does not have a direct equivalent to Java's `@EqualsAndHashCode` annotation, which is used for generating getter and setter methods. In this translation, I've omitted the equals method as it was not provided in the original code.

Also note that Python has no concept of "final" keyword like Java does. The private variable `help_type` can be accessed directly from outside the class without any restrictions.