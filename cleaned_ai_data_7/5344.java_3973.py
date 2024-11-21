class EmptyTextLine:
    def __init__(self, width_in_characters):
        self.width_in_characters = width_in_characters
        super().__init__(build_display_text(width_in_characters))

    @staticmethod
    def build_display_text(number_of_characters):
        return ' ' * number_of_characters

    def is_validated(self):
        return True

    def copy(self):
        return EmptyTextLine(self.width_in_characters)

    def matches(self, other_line):
        if isinstance(other_line, TextLine):
            return False  # empty line never match
        else:
            raise Exception("Invalid type")

    def update_color(self, other_validatable_line, invalid_color):
        if not isinstance(invalid_color, tuple) and len(invalid_color) != 3:
            raise TypeError("Color must be a RGB value")
        if other_validatable_line is None or (isinstance(other_validatable_line, EmptyTextLine)):
            return
        elif not isinstance(other_validatable_line, TextLine):
            raise Exception("Invalid type")

    def __str__(self):
        return "<FixedWidthEmptyTextLine>"
