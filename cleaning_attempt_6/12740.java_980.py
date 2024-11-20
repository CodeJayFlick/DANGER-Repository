class AutomaticCommentFieldLocation:
    def __init__(self, program=None, addr=None, component_path=None, comment=None, row=0, char_offset=0, current_comment_row=0):
        super().__init__()
        self.current_comment_row = current_comment_row

    @property
    def current_comment_row(self):
        return self._current_comment_row

    @current_comment_row.setter
    def current_comment_row(self, value):
        self._current_comment_row = value

    def __hash__(self):
        result = super().__hash__()
        result += hash(self.current_comment_row)
        return result

    def __eq__(self, other):
        if not isinstance(other, AutomaticCommentFieldLocation):
            return False
        if not super().__eq__(other):
            return False
        if self.current_comment_row != other.current_comment_row:
            return False
        return True

    def save_state(self, obj):
        super().save_state(obj)
        obj['current_comment_row'] = self.current_comment_row

    def restore_state(self, program, obj):
        super().restore_state(program, obj)
        if 'current_comment_row' in obj:
            self.current_comment_row = obj.pop('current_comment_row')

    def __str__(self):
        return f"{super().__str__()}, Comment Row = {self.current_comment_row}"
