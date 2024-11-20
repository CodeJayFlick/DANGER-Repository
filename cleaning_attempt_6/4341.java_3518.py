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
