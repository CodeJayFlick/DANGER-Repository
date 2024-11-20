class StringNotStartsWithColumnConstraint:
    def __init__(self, spec):
        super().__init__(spec)

    @property
    def name(self):
        return "Does Not Start With"

    def accepts(self, value: str, context) -> bool:
        return not super().accepts(value, context)

    @property
    def group(self):
        return "z string"

    def copy(self, new_pattern_string: str) -> 'StringNotStartsWithColumnConstraint':
        return StringNotStartsWithColumnConstraint(new_pattern_string)
