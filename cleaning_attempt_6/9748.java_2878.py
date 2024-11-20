class InRangeColumnConstraint:
    def __init__(self, name: str = "In Range", min_value: object, max_value: object, editor_provider):
        super().__init__(name, min_value, max_value, editor_provider)

    @property
    def accepts(self) -> bool:
        if value is None:
            return False
        return (value >= self.min_value and value <= self.max_value)

    def copy(self, min: object, max: object):
        return InRangeColumnConstraint(self.name, min, max, self.editor_provider)
