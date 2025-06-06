class Patterns:
    def __init__(self, info):
        self.patterns = [pattern[0] for pattern in info]
        self.ts = [pattern[1] for pattern in info]

    @property
    def patterns(self):
        return self._patterns

    def get_info(self, matched_pattern):
        if isinstance(matched_pattern, int) and 0 <= matched_pattern < len(self.patterns):
            return self.ts[matched_pattern]
        else:
            raise ValueError("Invalid pattern index")
