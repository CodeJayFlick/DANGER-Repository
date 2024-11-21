Here is a translation of the Java code into equivalent Python code:

```Python
class GenericByteSequencePattern:
    def __init__(self, bytes_sequence: list[int], action):
        self.bytes_sequence = bytes_sequence
        self.action = action

    @classmethod
    def from_bytes_and_action(cls, bytes_sequence: list[int], action):
        return cls(bytes_sequence, action)

    @classmethod
    def from_bytes_mask_and_action(cls, bytes_sequence: list[int], mask: list[int], action):
        return cls([bytes(x) for x in zip(bytes_sequence, mask)], action)


class GenericMatchAction:
    pass


# Example usage:

def my_match_action(data_type):
    print(f"Matched {data_type}")

pattern = GenericByteSequencePattern.from_bytes_and_action([0x01, 0x02], lambda data_type: my_match_action(data_type))

another_pattern = GenericByteSequencePattern.from_bytes_mask_and_action([0x03, 0x04], [0x05, 0x06], lambda data_type: my_match_action(data_type))
```

This Python code does not have direct equivalent of Java's generics. However, it achieves similar functionality by using type hints and the `lambda` function to define a match action.

The `GenericByteSequencePattern` class has two constructors (`from_bytes_and_action` and `from_bytes_mask_and_action`) that take in byte sequences (or both bytes sequence and mask) along with an action. The pattern is initialized with these values, but it does not have direct access to the underlying data types like Java's generics do.

The `GenericMatchAction` class is a placeholder for any match action, which can be defined by the user. In this example, we define two actions: one that prints out the matched data type and another that does nothing (just an empty function).