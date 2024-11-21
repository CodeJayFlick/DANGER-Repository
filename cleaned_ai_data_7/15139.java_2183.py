class Student:
    def __init__(self, id: int, name: str, address: str):
        self.id = id
        self.name = name
        self.address = address

    @property
    def id(self) -> int:
        return self._id

    @property
    def name(self) -> str:
        return self._name

    @property
    def address(self) -> str:
        return self._address
