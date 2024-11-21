class PreservingWhitespaceHandler:
    def count_spaces(self, s: str, offset: int) -> int:
        return 0  # we count no spaces

    def trim(self, s: str) -> str:
        return s  # no trimming
