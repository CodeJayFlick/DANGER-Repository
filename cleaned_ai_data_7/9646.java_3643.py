import re

class StartsWithTextFilter:
    def __init__(self, filter_text: str, case_sensitive: bool = True, allow_globbing: bool = False):
        self.filter_text = filter_text
        self.case_sensitive = case_sensitive
        self.allow_globbing = allow_globbing

    def create_pattern(self) -> re.Pattern:
        options = 0
        if not self.case_sensitive:
            options |= re.I
        return re.compile(f"^{re.escape(self.filter_text)}", flags=options)

    def is_sub_filter_of(self, parent_filter: 'StartsWithTextFilter') -> bool:
        if not isinstance(parent_filter, StartsWithTextFilter):
            return False

        if self.case_sensitive != parent_filter.case_sensitive or \
           self.allow_globbing != parent_filter.allow_globbing:
            return False

        return self.filter_text.startswith(parent_filter.filter_text)
