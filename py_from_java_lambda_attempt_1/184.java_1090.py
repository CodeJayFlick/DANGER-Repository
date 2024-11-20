Here's your Java code translated into equivalent Python:

```Python
class RegisterRow:
    def __init__(self, provider: 'DebuggerRegistersProvider', number: int, register: 'Register') -> None:
        self.provider = provider
        self.number = number
        self.register = register
        self.favorite = provider.is_favorite(register)

    @property
    def favorite(self) -> bool:
        return self._favorite

    @favorite.setter
    def favorite(self, value: bool) -> None:
        if value != self._favorite:
            self._favorite = value
            self.provider.set_favorite(self.register, value)

    @property
    def number(self) -> int:
        return self._number

    @property
    def register(self) -> 'Register':
        return self._register

    @property
    def name(self) -> str:
        return self.register.name

    def is_value_editable(self) -> bool:
        return self.provider.can_write_target_register(self.register)

    def set_value(self, value: int | float) -> None:
        try:
            self.provider.write_register_value(self.register, value)
        except Exception as e:
            # Catch this here so cell editor relinquishes focus
            print(f"Cannot edit Register Value. Error message: {e}")

    @property
    def value(self) -> int | float:
        return self.provider.get_register_value(self.register)

    def set_data_type(self, data_type: 'DataType') -> None:
        self.provider.write_register_data_type(self.register, data_type)

    @property
    def data_type(self) -> 'DataType':
        return self.provider.get_register_data_type(self.register)

    # TODO: setValueRepresentation. Requires support from data types.

    def get_representation(self) -> str:
        return self.provider.get_register_value_representation(self.register)

    def is_known(self) -> bool:
        return self.provider.is_register_known(self.register)

    def is_changed(self) -> bool:
        return self.provider.is_register_changed(self.register)
```

Note that Python does not have direct equivalent of Java's `package`, so I omitted it. Also, the translation assumes that you are using a Python IDE or an environment where type hints and annotations work as expected.