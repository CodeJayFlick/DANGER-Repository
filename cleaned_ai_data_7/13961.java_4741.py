class Customer:
    def __init__(self, id: int, first_name: str, last_name: str):
        self.id = id
        self.first_name = first_name
        self.last_name = last_name

    @property
    def id(self) -> int:
        return self._id

    @id.setter
    def id(self, value: int) -> None:
        self._id = value

    @property
    def first_name(self) -> str:
        return self._first_name

    @first_name.setter
    def first_name(self, value: str) -> None:
        self._first_name = value

    @property
    def last_name(self) -> str:
        return self._last_name

    @last_name.setter
    def last_name(self, value: str) -> None:
        self._last_name = value

    def __str__(self):
        return f"Customer(id={self.id}, first_name='{self.first_name}', last_name='{self.last_name}')"

    def __eq__(self, other):
        if not isinstance(other, Customer):
            return False
        return (self.id == other.id and 
                self.first_name == other.first_name and 
                self.last_name == other.last_name)
