Here is the equivalent Python code:

```Python
class EquateInfo:
    def __init__(self, name: str, value: int, ref_addr=None, op_index=-1, dynamic_hash=0):
        self.name = name
        self.value = value
        self.ref_addr = ref_addr
        self.op_index = op_index
        self.dynamic_hash = dynamic_hash

    def get_name(self) -> str:
        return self.name

    def get_value(self) -> int:
        return self.value

    def get_reference_address(self):
        return self.ref_addr

    def get_operand_index(self) -> int:
        return self.op_index

    def get_dynamic_hash(self) -> int:
        return self.dynamic_hash

    def __str__(self) -> str:
        return f"Name={self.name}, value={self.value}, RefAddr={self.ref_addr}, opIndex={self.op_index}, dynamicHash=0x{hex(self.dynamic_hash)[2:]}"

# Example usage
equate_info = EquateInfo("my_equate", 123, ref_addr="0xdeadbeef", op_index=5)
print(equate_info)  # Output: Name=my_equate, value=123, RefAddr=0xdeadbeef, opIndex=5, dynamicHash=0x
```

Note that I've used Python's type hints to indicate the types of the parameters and return values. This is not strictly necessary for a simple class like this one, but it can be helpful in larger programs where you want to ensure that function arguments are being passed with the correct types.

I also took some liberties with the `__str__` method to make it more Pythonic; instead of concatenating strings using commas and pluses, I used an f-string.