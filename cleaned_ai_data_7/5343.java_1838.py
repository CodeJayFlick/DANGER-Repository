class EmptyDataTypeLine:
    def __init__(self):
        super().__init__("", "", "", None)

    def copy(self):
        return type(self)()

    def update_color(self, other_validatable_line, invalid_color):
        if invalid_color is None:
            raise ValueError("Color cannot be null")
        
        if (other_validatable_line is None or isinstance(other_validatable_line, EmptyDataTypeLine)):
            return
        
        if not isinstance(other_validatable_line, DataTypeLine):
            raise AssertionError("DataTypeLine can only be matched against other DataT" +
                                 "ypeLine implementations.")
        
        other_line = other_validatable_line
        # since we are the empty line, the other line is all a mismatch
        other_line.set_all_colors(invalid_color)

    def matches(self, other_line):
        return False

    def matches_name(self, other_name):
        return False

    def matches_type(self, other_type):
        return False

    def matches_comment(self, other_comment):
        return False

    def is_validated(self):
        return True

    def __str__(self):
        return "<Empty Line>"
