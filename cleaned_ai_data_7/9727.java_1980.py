import datetime

class AtLeastDateColumnConstraint:
    def __init__(self, min_value: datetime.date, editor_provider):
        self.min_value = min_value
        self.editor_provider = editor_provider

    @property
    def name(self) -> str:
        return "On or After Date"

    @property
    def group_name(self) -> str:
        return ""

    def accepts(self, value: datetime.date, context=None):
        if value is None:
            return False
        return value >= self.min_value

    def copy(self, new_min_value: datetime.date):
        return AtLeastDateColumnConstraint(new_min_value, self.editor_provider)
