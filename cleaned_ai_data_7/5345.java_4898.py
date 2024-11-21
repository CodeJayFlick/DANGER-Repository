class EmptyVariableTextLine:
    def __init__(self, number_of_characters):
        self.number_of_characters = number_of_characters
        super().__init__(build_display_text(number_of_characters >> 1), build_display_text(number_of_characters >> 1), None)

    @staticmethod
    def build_display_text(number_of_characters):
        buffy = "<TT>"
        for i in range(number_of_characters):
            buffy += " "
        buffy += "</TT>"
        return buffy

    def copy(self):
        return EmptyVariableTextLine(self.number_of_characters)

    def update_color(self, other_validatable_line, invalid_color):
        if invalid_color is None:
            raise ValueError("Color cannot be null")
        
        if (other_validatable_line is None or isinstance(other_validatable_line, type(self))):
            return
        
        if not isinstance(other_validatable_line, VariableTextLine):
            raise AssertionError("VariableTextLine can only be matched against other VariableTextLine implementations.")
        
        other_line = other_validatable_line
        other_line.set_all_colors(invalid_color)

    def matches(self, other_validatable_line):
        return False

    def is_validated(self):
        return True

    def matches_name(self, other_name):
        return False

    def matches_type(self, other_type):
        return False

    def __str__(self):
        return "<EmptyVariableTextLine>"
