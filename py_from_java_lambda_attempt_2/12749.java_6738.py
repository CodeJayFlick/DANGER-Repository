Here is the translation of the Java code to Python:

```Python
class CodeUnitUserDataChangeRecord:
    def __init__(self, property_name: str, code_unit_addr: int, old_value: object, new_value: object):
        self.property_name = property_name
        self.code_unit_addr = code_unit_addr
        self.old_value = old_value
        self.new_value = new_value

    @property
    def get_property_name(self) -> str:
        return self.property_name

    @property
    def get_code_unit_address(self) -> int:
        return self.code_unit_addr

    @property
    def get_old_value(self) -> object:
        return self.old_value

    @property
    def get_new_value(self) -> object:
        return self.new_value


# Example usage:

record = CodeUnitUserDataChangeRecord("propertyName", 123, "old value", "new value")
print(record.get_property_name)
print(record.get_code_unit_address)
print(record.get_old_value)
print(record.get_new_value)
```

Note that Python does not have direct equivalents to Java's `private` and `final`, so I did not include those in the translation. Also, Python has a different way of handling serialization (it uses the `pickle` module), but since you didn't mention anything about deserialization, I left it out as well.