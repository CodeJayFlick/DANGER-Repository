Here is the translation of the given Java code into equivalent Python:

```Python
class AbstractGdbEventWithString:
    def __init__(self, tail):
        self.tail = tail

    @classmethod
    def from_tail(cls, tail):
        return cls(tail)

    @classmethod
    def from_info(cls, info):
        return cls(str(info))

    def parse_info(self) -> str:
        import re
        pattern = r"(\w+)"
        match = re.search(pattern, self.tail)
        if match:
            return match.group(0).strip()
        else:
            raise ValueError("Failed to parse the tail")

class GdbMiParser:
    @classmethod
    def parse_string(cls, s):
        # Implement your parsing logic here. For now, just strip any leading/trailing whitespace.
        return str(s).strip()

# Example usage:

if __name__ == "__main__":
    event = AbstractGdbEventWithString.from_tail("some info")
    print(event.parse_info())

    event2 = AbstractGdbEventFromString.from_info({"key": "value"})
    print(event2.parse_info())
```

This Python code defines two classes: `AbstractGdbEventWithString` and `GdbMiParser`. The former is an abstract class that represents a GDB event with string information, while the latter provides parsing functionality for strings.