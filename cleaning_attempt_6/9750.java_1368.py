class NotInDateRangeColumnConstraint:
    def __init__(self, min_value: 'LocalDate', max_value: 'LocalDate', editor_provider):
        super().__init__("Not Between Dates", min_value, max_value, editor_provider, "date")

    def accepts(self, value: 'LocalDate', context) -> bool:
        if value is None:
            return False
        return value < self.min_value or value > self.max_value

    def copy(self, min_value: 'LocalDate', max_value: 'LocalDate') -> 'NotInDateRangeColumnConstraint':
        return NotInDateRangeColumnConstraint(min_value, max_value, self.editor_provider)
