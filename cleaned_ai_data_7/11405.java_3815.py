class AssemblyParseErrorResult:
    SUGGESTIONS_THRESHOLD = 10

    def __init__(self, got: str, suggestions: set):
        self.buffer = got
        self.suggestions = suggestions

    @property
    def is_error(self) -> bool:
        return True

    def describe_error(self) -> str:
        trunc_suggestions = self.suggestions.copy()
        if len(trunc_suggestions) <= self.SUGGESTIONS_THRESHOLD:
            pass
        else:
            trunc_suggestions.clear()
            for s in list(self.suggestions)[:self.SUGGESTIONS_THRESHOLD]:
                trunc_suggestions.add(s)
            trunc_suggestions.add("...")
        return f"Syntax Error: Expected {trunc_suggestions}. Got {self.buffer}"

    @property
    def suggestions(self) -> set:
        return frozenset(self.suggestions)

    @property
    def buffer(self) -> str:
        return self.buffer

    def __str__(self):
        return self.describe_error()
