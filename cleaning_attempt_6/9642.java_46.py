class MatchesExactlyTextFilterFactory:
    def __init__(self, case_sensitive: bool, allow_globbing: bool):
        self.case_sensitive = case_sensitive
        self.allow_globbing = allow_globbing

    def get_text_filter(self, text: str) -> 'MatchesExactlyTextFilter':
        if not text or len(text) == 0:
            return None
        return MatchesExactlyTextFilter(text, self.case_sensitive, self.allow_globbing)


class MatchesExactlyTextFilter:
    def __init__(self, text: str, case_sensitive: bool, allow_globbing: bool):
        self.text = text
        self.case_sensitive = case_sensitive
        self.allow_globbing = allow_globbing

# Example usage:
factory = MatchesExactlyTextFilterFactory(True, False)
filter_ = factory.get_text_filter("Hello")
print(filter_)  # Output: <MatchesExactlyTextFilter object>
