class KeyRange:
    def __init__(self, min_key: int, max_key: int):
        self.min_key = min_key
        self.max_key = max_key

    def contains(self, key: int) -> bool:
        return min_key <= key <= max_key

    def length(self) -> int:
        return (max_key - min_key + 1)
