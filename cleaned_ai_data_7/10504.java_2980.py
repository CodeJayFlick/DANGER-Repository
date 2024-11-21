class TrimmingWhitespaceHandler:
    def count_spaces(self, s: str, offset: int) -> int:
        for i in range(offset, len(s)):
            if not s[i].isspace():
                return i - offset
        return len(s) - offset  # all whitespace

    def trim(self, s: str) -> str:
        return s.strip()
