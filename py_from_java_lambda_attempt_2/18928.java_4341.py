Here is the translation of the Java code to Python:

```Python
class SomeEntity:
    def __init__(self, value: int):
        self.value = value

    @property
    def value(self) -> int:
        return self._value

# Note that in Python, we don't need annotations for not null or min/max values.
```

Note that the equivalent of Java's `@JsonCreator` and `@JsonProperty` are not directly available in Python. The JSON serialization/deserialization is typically handled by libraries like `json` or `marshmallow`.