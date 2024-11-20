from abc import ABC, abstractmethod

class ColumnConstraint(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def accepts(self, value: object, context: dict) -> bool:
        """Compares value against the current constraint value to determine acceptance; true if value satisfies the constraints' value, false otherwise"""
        raise NotImplementedError("Method not implemented")

    def as_string(self) -> str:
        return f"{self.get_name()} {self.get_constraint_value_tooltip()}"


class ColumnConstraintEditor(ABC):
    @abstractmethod
    def get_editor(self, column_data_source: object) -> object:
        """Returns a ColumnConstraintEditor which will provide gui components for users to edit the constraint values"""
        raise NotImplementedError("Method not implemented")


class TableFilterContext(dict):
    pass

class ColumnData(object):
    pass


def main():
    # Example usage
    class MyColumnConstraint(ColumnConstraint):
        def __init__(self, name: str, value: object):
            self.name = name
            self.value = value

        def accepts(self, value: object, context: dict) -> bool:
            return value == self.value

        def get_name(self) -> str:
            return self.name

    my_constraint = MyColumnConstraint("My Constraint", "Hello")
    print(my_constraint.as_string())  # Output: My Constraint Hello


if __name__ == "__main__":
    main()
