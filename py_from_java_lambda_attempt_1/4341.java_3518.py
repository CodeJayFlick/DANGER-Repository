Here is the translation of the given Java code into Python:

```Python
class StringDataInstanceColumnConstraint:
    def get_group(self):
        return "string"

    def get_constraint_value_string(self):
        return ""

    @property
    def column_type(self):
        from ghidra.program.model.data import StringDataInstance
        return type(StringDataInstance)

    def parse_constraint_value(self, constraint_value_string: str, data_source) -> 'StringDataInstanceColumnConstraint':
        return self

# Note that Python does not have direct equivalent of Java's abstract class.
```

Note that the `abstract` keyword in Java is used to declare an abstract class or method. In Python, we don't need this as classes are always concrete and can be instantiated directly.