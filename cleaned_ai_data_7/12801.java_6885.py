class EolCommentFieldLocation:
    def __init__(self, program: 'Program', addr: int, component_path: list[int], 
                 comment: str, displayable_comment_row: int, char_offset: int):
        super().__init__(program, addr, component_path, [comment], 3, displayable_comment_row, char_offset)

    def __init__(self):  # Default constructor needed for restoring
        super().__init__()
