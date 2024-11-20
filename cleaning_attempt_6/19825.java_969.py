class SimpleLiteral:
    def __init__(self, data: list[T], c: type(T), and_: bool):
        assert data != []  # Check if data is not empty
        self.data = data
        self.c = c
        self.and_ = len(data) == 1 or and_
        self.is_default = False

    def __init__(self, data: T, is_default: bool):
        self.__init__([data], type(data), True)

    @staticmethod
    def get_random(lst: list[T]) -> T:
        return random.choice(lst)

    def init(self) -> bool:
        raise NotImplementedError()

    def get_array(self) -> list[T]:
        return self.data

    def get_single(self) -> T:
        if len(self.data) == 1 or not self.and_:
            return self.get_random(self.data)
        else:
            return None

    @property
    def source(self):
        return self._source

    @source.setter
    def source(self, value: UnparsedLiteral | None):
        self._source = value

class ConvertedLiteral(SimpleLiteral[T]):
    def __init__(self, literal: SimpleLiteral[T], data: list[R], to: type(R)):
        super().__init__(data, to, True)
