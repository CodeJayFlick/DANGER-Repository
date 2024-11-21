Here is the translation of the Java code into Python:

```Python
class GenericCompositeDataTypeLocationDescriptor:
    def __init__(self, location: 'GenericCompositeDataTypeProgramLocation', program):
        super().__init__(location, program)
        self.field_name = location.get_field_name()
        self.type_and_field_name = f"{get_data_type_name()}.{field_name}"
        self.label = generate_label()

    @property
    def type_name(self) -> str:
        return f"{super().type_name}.{self.field_name}"

    def get_references(self, accumulator: 'Accumulator[LocationReference]', monitor):
        current_data_type = (Composite)(get_data_type())
        ReferenceUtils.find_data_type_references(accumulator, current_data_type, self.field_name, program, use_dynamic_searching, monitor)

    @property
    def label(self) -> str:
        return f"\"{original_data_type.name}\".{self.field_name} (DataType)"

    def __eq__(self, other):
        if self is other:
            return True

        if not isinstance(other, GenericCompositeDataTypeLocationDescriptor):
            return False

        other_descriptor = other
        return get_data_type().equals(other_descriptor.get_data_type()) and self.field_name == other_descriptor.field_name

    @property
    def highlights(self) -> list['Highlight']:
        current_address = address_for_highlight_object(highlight_object)
        if not is_in_addresses(current_address):
            return []

        if isinstance(highlight_object, Data) and MnemonicFieldFactory in [f.__class__ for f in field_factory]:
            # Not sure if we should ever highlight the mnemonic. It would only be for data.
            pass

        elif LabelFieldFactory in [f.__class__ for f in field_factory]:
            # It would be nice to highlight the label that points into data structures.
            # However, the label is on the parent address, which is not in our list of matches
            # when we are offcut. Further, using the program to lookup each address that 
            # comes in to see if it is our paren' taddress seems too expensive, as highlighting
            # code is called for every paint operation.
            pass

        elif OperandFieldFactory in [f.__class__ for f in field_factory]:
            offset = text.find(type_and_field_name)
            if offset != -1:
                return [Highlight(offset, offset + len(type_and_field_name) - 1, highlight_color)]

        elif FieldNameFieldFactory in [f.__class__ for f in field_factory]:
            if text.lower() == self.field_name.lower():
                return [Highlight(0, len(text), highlight_color)]
            elif text.lower().startswith(get_data_type_name()):
                return [Highlight(0, len(text), highlight_color)]

        return []
```

Please note that Python does not support Java's `@Override` annotation. Also, some methods in the original code are not implemented here as they seem to be specific to a certain context or environment and may require additional information to correctly translate them into Python.