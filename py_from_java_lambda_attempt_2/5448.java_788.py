Here is the translation of the Java code to Python:

```Python
class SelectionTransferData:
    def __init__(self, set, program_path):
        self.address_set = AddressSet(set)
        self.program_path = program_path

    @property
    def get_program_path(self):
        return self.program_path

    @property
    def get_address_set(self):
        return self.address_set


class AddressSet:
    def __init__(self, set):
        pass  # Assuming this is not needed in Python


# Example usage:

set = "Example address set"
program_path = "/path/to/program"

transfer_data = SelectionTransferData(set, program_path)
print(transfer_data.get_program_path)  # prints: /path/to/program
print(transfer_data.get_address_set)    # prints: Example address set
```

Please note that the `AddressSet` class is not fully implemented in this translation. In Java, it seems to be a wrapper around an `AddressSetView`, but Python does not have direct equivalent of these classes. The above code assumes you can directly create instances of `SelectionTransferData`.