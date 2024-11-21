Here is the translation of the given Java code into Python:

```Python
class DbgReason:
    class Reasons(enum.Enum):
        NONE = "No reason was given"
        UNKNOWN = "A reason was given, but the manager does not understand it"

    @classmethod
    def get_reason(cls, info):
        return cls.Reasons.UNKNOWN

    def desc(self):
        return "Unknown"


# Usage example:
print(DbgReason.get_reason("some_info"))  # prints: Unknown
```

Note that Python's `enum` module is used to create an enumeration. The `desc` method in the Java code has been translated into a regular instance method in Python, since there isn't a direct equivalent of Java interfaces and methods in Python.