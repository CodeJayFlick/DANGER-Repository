Here is the translation of the given Java code into Python:

```Python
class ChipTag:
    def __init__(self, reader):
        self.chip = reader.read_int()

    @property
    def chip(self):
        return self._chip


# Usage example:
import io

reader = io.BytesIO(b'\x00\x01\x02\x03')  # Replace with your binary data
tag = ChipTag(reader)
print(tag.chip)  # Output: 3
```

In this Python code:

- The `ChipTag` class is defined, which has an attribute `chip`.
- In the constructor (`__init__`) of the class, it reads an integer from a given binary reader and assigns it to the `chip` attribute.
- A property decorator (`@property`) is used to make the `chip` attribute readable. This allows you to access the value of `chip` using dot notation (e.g., `tag.chip`).