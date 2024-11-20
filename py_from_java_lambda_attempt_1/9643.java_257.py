Here is the translation of the Java code to Python:
```
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
```
Note that I've used the `re` module for regular expression operations. Also, Python's built-in equality operator (`==`) is used instead of implementing a custom `equals()` method.

Additionally, since there are no specific requirements mentioned in the Java code (e.g., handling null values), I have not added any additional checks or logic to handle these cases explicitly.