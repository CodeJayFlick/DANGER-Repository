class ArrayIterator:
    def __init__(self, array: list | None = None, start: int = 0) -> None:
        self.array = array
        self.index = start

    def hasNext(self) -> bool:
        if not self.array:
            return False
        return self.index < len(self.array)

    def next(self) -> object | None:
        if not self.array or self.index >= len(self.array):
            raise StopIteration
        result = self.array[self.index]
        self.index += 1
        return result

    def remove(self) -> None:
        raise NotImplementedError("remove is not supported for arrays")
