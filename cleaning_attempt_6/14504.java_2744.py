class Result:
    def __init__(self, data):
        self.data = data


class ArrayResult(Result):
    def __init__(self, data: list[list[int]]):
        super().__init__(data)
