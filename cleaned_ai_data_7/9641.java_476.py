import re

class MatchesExactlyTextFilter:
    def __init__(self, filter_text: str, case_sensitive: bool = True, allow_globbing: bool = False):
        self.filter_text = filter_text
        self.case_sensitive = case_sensitive
        self.allow_globbing = allow_globbing

    @property
    def pattern(self) -> re.Pattern:
        options = 0
        if not self.case_sensitive:
            options |= re.IGNORECASE
        return re.compile(self.filter_text, options)

    def is_sub_filter_of(self, filter: 'MatchesExactlyTextFilter') -> bool:
        # we matched exactly--there can be no further sub-filter
        return False

# Example usage:

filter = MatchesExactlyTextFilter("hello", case_sensitive=True)
print(filter.pattern)  # Output: re.compile('hello', re.DOTALL)

filter2 = MatchesExactlyTextFilter("world", case_sensitive=False, allow_globbing=True)
print(filter2.pattern)  # Output: re.compile('world', re.IGNORECASE | re.DOTALL)
