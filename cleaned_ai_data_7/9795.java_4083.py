class MappedColumnConstraintEditor:
    def __init__(self, constraint: 'MappedColumnConstraint', delegate_editor):
        self.constraint = constraint
        self.delegate_editor = delegate_editor

    @property
    def inline_component(self) -> object:
        return self.delegate_editor.inline_component()

    @property
    def detail_component(self) -> object:
        return self.delegate_editor.detail_component()

    def get_value(self) -> 'ColumnConstraint':
        value = self.delegate_editor.get_value()
        return self.constraint.copy(value)

    def set_value(self, value: 'ColumnConstraint'):
        new_constraint = MappedColumnConstraint(value)
        self.delegate_editor.set_value(new_constraint.get_delegate())

    def reset(self):
        self.delegate_editor.reset()

    @property
    def has_valid_value(self) -> bool:
        return self.delegate_editor.has_valid_value

    @property
    def error_message(self) -> str:
        return self.delegate_editor.error_message

    def add_change_listener(self, listener: 'ChangeListener'):
        self.delegate_editor.add_change_listener(listener)

    def remove_change_listener(self, listener: 'ChangeListener'):
        self.delegate_editor.remove_change_listener(listener)
