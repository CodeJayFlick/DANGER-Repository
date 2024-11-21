class EmptyAddressRangeIterator:
    def __init__(self):
        pass

    def next(self) -> object:
        return None

    def hasNext(self) -> bool:
        return False

    def remove(self) -> None:
        raise NotImplementedError("Method not implemented")

    def __iter__(self):
        return self
