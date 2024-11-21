class EolCommentFieldLocation:
    def __init__(self, program=None, addr=None, component_path=None, comment=None, displayable_comment_row=0, char_offset=0, current_comment_row=0):
        super().__init__(program, addr, component_path, comment, 'EOL_COMMENT', displayable_comment_row, char_offset)
        self.current_comment_row = current_comment_row

    def __str__(self):
        return f"{super().__str__()}, Comment Row = {self.current_comment_row}"

    def get_current_comment_row(self):
        return self.current_comment_row
