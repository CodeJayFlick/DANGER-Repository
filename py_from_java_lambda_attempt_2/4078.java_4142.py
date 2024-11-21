Here is the translation of the Java code into equivalent Python code:

```Python
class VariableTypeLocationDescriptor:
    def __init__(self, location, program):
        super().__init__(location, program)
        
        if not isinstance(location, VariableTypeFieldLocation):
            raise AssertionError("Unexpected ProgramLocation type - Cannot create a LocationDescriptor for type: " + str(location))

    def generate_label(self):
        return self.get_data_type_name()

    def get_data_type_name(self):
        return self.original_data_type.display_name

    def get_source_data_type(self):
        var = (location_var := location).variable
        return var.data_type

    def get_base_data_type(self):
        return ReferenceUtils.get_base_data_type(self.source_data_type)

    def get_highlights(self, text: str, object: any, field_factory_class: type[FieldFactory], highlight_color: tuple[int, int, int]) -> list[tuple]:
        if isinstance(field_factory_class, VariableTypeFieldFactory) and isinstance(object, Variable):
            # compare against the underlying datatype, since the display text is different
            variable = object
            other_base_data_type = ReferenceUtils.get_base_data_type(variable.data_type)
            if other_base_data_type == self.base_data_type:
                return [(0, len(text) - 1, highlight_color)]
        
        return super().get_highlights(text, object, field_factory_class, highlight_color)

class VariableTypeFieldLocation:
    pass

class FieldFactory:
    pass
```

Please note that Python does not have direct equivalent of Java's `@Override` annotation. The method overriding is done by using the same name as in parent class and calling it with `super()`.

Also, I've used type hints for better readability but please be aware that they are optional in Python and can be removed if needed.