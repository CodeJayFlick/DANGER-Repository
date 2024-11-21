Here's a translation of your Java interface into Python:

```Python
class ParameterDefinition:
    def __init__(self):
        self.ordinal = None
        self.data_type = None
        self.name = None
        self.length = 0
        self.comment = ''

    def get_ordinal(self):
        return self.ordinal

    def set_ordinal(self, ordinal):
        self.ordinal = ordinal

    def get_data_type(self):
        return self.data_type

    def set_data_type(self, data_type):
        if not isinstance(data_type, str):  # Assuming the data type is a string
            raise ValueError("Invalid parameter datatype specified")
        self.data_type = data_type

    def get_name(self):
        return self.name

    def set_name(self, name):
        self.name = name

    def get_length(self):
        return self.length

    def set_length(self, length):
        if not isinstance(length, int):  # Assuming the length is an integer
            raise ValueError("Invalid parameter length specified")
        self.length = length

    def get_comment(self):
        return self.comment

    def set_comment(self, comment):
        self.comment = comment

    def is_equivalent(self, other):
        if not isinstance(other, ParameterDefinition):  # Assuming the equivalent object should be a ParameterDefinition
            raise ValueError("Invalid parameter definition specified")
        return (self.ordinal == other.get_ordinal() and 
                self.data_type.lower() == other.get_data_type().lower())

    def __eq__(self, other):
        if not isinstance(other, ParameterDefinition):  # Assuming the equivalent object should be a ParameterDefinition
            raise ValueError("Invalid parameter definition specified")
        return (self.ordinal == other.get_ordinal() and 
                self.data_type.lower() == other.get_data_type().lower())
```

This Python code defines a class `ParameterDefinition` with methods similar to those in your Java interface. The equivalent comparison method (`is_equivalent`) is also implemented, along with the magic method (`__eq__`) for direct equality comparisons between instances of this class.