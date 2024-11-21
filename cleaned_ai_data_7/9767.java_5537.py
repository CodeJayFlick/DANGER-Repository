class StringContainsColumnConstraint:
    def __init__(self, pattern_string):
        super().__init__(pattern_string)

    @property
    def name(self):
        return "Contains"

    def copy(self, new_pattern_string):
        return type(self)(new_pattern_string)

    def generate_matches_pattern(self, pattern_string):
        import re
        return re.compile(f"({re.escape(pattern_string).lower()})", flags=re.IGNORECASE | re.UNICODE)
