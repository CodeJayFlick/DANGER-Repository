Here is the translation of the Java code into Python:

```Python
class StringAddedEvent:
    def __init__(self, string_data_type: object, address: int, length: int):
        super().__init__(string_data_type, address, length)

    def process(self, model: object, options: dict) -> None:
        new_string = FoundString(address=self.address, length=self.length, data_type=self.data_type)
        row = model.get_row_index(new_string)

        existing_string = None
        if 0 <= row < len(model):
            existing_string = model[row]
            if not self.is_address_equal(existing_string.address, address):
                existing_string = None

        if existing_string is None:
            existing_string = find_row_slow_way(model)
        
        if existing_string is None:
            if options.get('include_defined_strings'):
                new_string.set_defined_state(DefinedState.Defined)
                model.add_object(new_string)
            return
        
        self.update_match(existing_string, new_string)

        if existing_string.is_defined and not options['include_defined_strings']:
            model.remove_object(existing_string)
        elif existing_string.is_partially_defined and not options['include_patially_defined_strings']:
            model.remove_object(existing_string)
        else:
            model.update_object(existing_string)


    def update_match(self, existing_string: object, new_string: object) -> None:
        min_address = self.get_min_address(existing_string.address, new_string.address)
        max_address = self.get_max_address(existing_string.end_address, new_string.end_address)

        length = (max_address - min_address).bit_length() + 1

        existing_string.set_address(min_address)
        existing_string.set_length(length)
        existing_string.set_defined_state(DefinedState.Partially Defined)


class FoundString:
    def __init__(self, address: int, length: int, data_type: object):
        self.address = address
        self.length = length
        self.data_type = data_type

    @property
    def defined_state(self) -> str:
        return 'Defined' if self._defined_state == DefinedState.Defined else ('Partially Defined' if self._defined_state == DefinedState.Partially Defined else None)

    @defined_state.setter
    def set_defined_state(self, state: object):
        self._defined_state = state


class StringTableModel:
    def get_row_index(self, new_string) -> int:
        pass

    def add_object(self, obj) -> None:
        pass

    def remove_object(self, obj) -> None:
        pass

    def update_object(self, obj) -> None:
        pass
```

Note that the translation is not a direct conversion from Java to Python. Some parts of the code have been modified or re-written in order to make it more suitable for Python.

Also note that some methods and variables are missing their implementation because they were part of the original Java class, but there was no equivalent method or variable in the provided Python translation.