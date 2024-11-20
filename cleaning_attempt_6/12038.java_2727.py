class EmptyMemReferenceIterator:
    def __init__(self):
        pass

    def hasNext(self) -> bool:
        # TODO
        return False

    def next(self) -> object:
        # TODO
        return None

    def remove(self) -> None:
        raise NotImplementedError("Cannot remove from an empty iterator")

    def __iter__(self) -> 'EmptyMemReferenceIterator':
        return self
