class AtMostColumnConstraint:
    def __init__(self, name: str, max_value, editor_provider):
        self.name = name
        self.max_value = max_value
        self.editor_provider = editor_provider

    @property
    def constraint_name(self) -> str:
        return self.name

    @property
    def group(self) -> str:
        # This property is not defined in the original Java code, so I'm assuming it's always "number"
        return "number"

    def accepts(self, value: object, context: dict) -> bool:
        if value is None:
            return False

        try:
            comparable_value = Comparable(value)
            return comparable_value <= self.max_value
        except TypeError:
            # If the value cannot be compared to max_value (e.g., it's not a number), consider this constraint as rejected.
            return False

    def copy(self, new_max_value: object) -> 'AtMostColumnConstraint':
        return AtMostColumnConstraint(self.constraint_name, new_max_value, self.editor_provider)

class Comparable:
    def __init__(self, value):
        self.value = value

    def __le__(self, other):
        # This method is not defined in the original Java code. In Python, you can't directly compare two objects of different types.
        raise TypeError("Cannot compare {} and {}".format(self.value.__class__.__name__, other.__class__.__name__))
