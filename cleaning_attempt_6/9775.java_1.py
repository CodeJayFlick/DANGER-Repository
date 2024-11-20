import re

class StringStartsWithColumnConstraint:
    def __init__(self, pattern_string):
        super().__init__(pattern_string)

    @property
    def name(self):
        return "Starts With"

    def copy(self, new_pattern_string):
        return type(self)(new_pattern_string)

    def generate_matches_pattern(self, pattern_string):
        return re.compile(f"^{re.escape(pattern_string)}", re.IGNORECASE)
