Here is the translation of the given Java code into equivalent Python:

```Python
class MDContext:
    def __init__(self):
        self.backref_names = []
        self.backref_parameters_md_data_type = []
        self.backref_template_parameters_md_data_type = []

    def add_backref_name(self, name: str) -> None:
        self.backref_names.append(name)

    def get_backref_name(self, index: int) -> str:
        if 0 <= index < len(self.backref_names):
            return self.backref_names[index]
        else:
            raise Exception("Backref Names stack violation")

    def add_backref_function_parameter_md_data_type(self, dt: 'MDDataType') -> None:
        self.backref_parameters_md_data_type.append(dt)

    def get_backref_function_parameter_md_data_type(self, index: int) -> 'MDDataType':
        if 0 <= index < len(self.backref_parameters_md_data_type):
            return self.backref_parameters_md_data_type[index]
        else:
            raise Exception("Parameter stack violation")

    def add_backref_template_parameter_md_data_type(self, dt: 'MDDataType') -> None:
        self.backref_template_parameters_md_data_type.append(dt)

    def get_backref_template_parameter_md_data_type(self, index: int) -> 'MDDataType':
        if 0 <= index < len(self.backref_template_parameters_md_data_type):
            return self.backref_template_parameters_md_data_type[index]
        else:
            raise Exception("Template parameter stack violation")

class MDContextType(enum.Enum):
    MODIFIER = "MODIFIER"
    FUNCTION = "FUNCTION"
    TEMPLATE = "TEMPLATE"

def create_MD_Context(copy_from: 'MDContext', context_type: MDContextType) -> None:
    if context_type == MDContextType.MODIFIER:
        return copy_from
    elif context_type == MDContextType.FUNCTION:
        return copy_from
    else:
        backref_names = []
        backref_parameters_md_data_type = copy_from.backref_parameters_md_data_type.copy()
        backref_template_parameters_md_data_type = copy_from.backref_template_parameters_md_data_type.copy()

        return MDContext(backref_names, backref_parameters_md_data_type, backref_template_parameters_md_data_type)
```

Please note that Python does not have an exact equivalent to Java's `enum` type. Instead, we use the built-in `int` type and define a constant class for each enum value.

Also, in this translation, I used the `copy()` method of lists (`backref_names`, `backref_parameters_md_data_type`, and `backref_template_parameters_md_data_type`) to create copies when creating a new context. This is because Python's list objects are mutable by default, unlike Java where you need to explicitly use the `ArrayList` class for this purpose.

Finally, I used the built-in exception type (`Exception`) instead of defining an `MDException` class as in the original code.