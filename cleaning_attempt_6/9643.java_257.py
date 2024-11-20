class MatchesPatternTextFilter:
    def __init__(self, filter_text: str, case_sensitive: bool, allow_globbing: bool):
        self.case_sensitive = case_sensitive
        self.allow_globbing = allow_globbing
        super().__init__(filter_text)

    def matches(self, text: str) -> bool:
        pattern = re.compile(text)
        return pattern.match(text).group() if pattern.match(text) else False

    def __hash__(self):
        raise NotImplementedError("Not meant to put in hashing structures; the data for equals may change over time")

    def __eq__(self, other: object) -> bool:
        if self is other:
            return True
        if not isinstance(other, MatchesPatternTextFilter):
            return False

        if super().__eq__(other):
            if self.allow_globbing != other.allow_globbing or \
               self.case_sensitive != other.case_sensitive:
                return False
            return True
