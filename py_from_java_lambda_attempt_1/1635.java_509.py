Here is the translation of the given Java code into Python:

```Python
class LldbReason:
    class Reasons(enum.Enum):
        NONE = "No reason was given"
        UNKNOWN = "A reason was given, but the manager does not understand it"

    @classmethod
    def get_reason(cls, info):
        return cls.Reasons.UNKNOWN

    def desc(self):
        return "Unknown"


# Usage example:
reason = LldbReason.get_reason("some_info")
print(reason)  # prints: Unknown
```

Please note that Python's `enum` module is used to create an enumeration. The `@classmethod` decorator is used to define a class method, which can be called without creating an instance of the class.