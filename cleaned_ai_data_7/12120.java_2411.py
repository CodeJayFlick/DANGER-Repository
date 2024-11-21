class EmptyRecordIterator:
    INSTANCE = None

    def __init__(self):
        self.INSTANCE = self

    def has_next(self) -> bool:
        return False

    def has_previous(self) -> bool:
        return False

    def next(self) -> object:
        return None

    def previous(self) -> object:
        return None

    def delete(self) -> bool:
        return False
