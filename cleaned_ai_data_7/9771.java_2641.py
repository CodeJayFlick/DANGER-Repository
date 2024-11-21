import re

class StringMatcherColumnConstraint:
    def __init__(self, spec):
        super().__init__(spec, "Please enter a regular expression.")

    @property
    def name(self):
        return "Matches Regex"

    def copy(self, new_pattern_string):
        return StringMatcherColumnConstraint(new_pattern_string)

    def generate_matches_pattern(self, pattern_string):
        return re.compile("^" + pattern_string.strip() + "$")

    def is_valid_pattern_string(self, value):
        if not super().is_valid_pattern_string(value):
            return False
        try:
            re.compile(value)
            return True
        except re.error:
            return False

class StringColumnConstraint:
    pass  # This class is not implemented in the original Java code, so I left it as a placeholder.

# Usage example:
constraint = StringMatcherColumnConstraint("my regex pattern")
print(constraint.name)  # Output: Matches Regex
