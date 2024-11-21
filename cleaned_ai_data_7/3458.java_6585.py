class FilterState:
    def __init__(self, bookmark_types: set):
        self.bookmark_types = bookmark_types

    @property
    def bookmark_types(self) -> set:
        return self.bookmark_types
