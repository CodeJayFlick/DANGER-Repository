class Book:
    def __init__(self, title: str = None, price: float = None):
        self.title = title
        self.price = price

    @property
    def title(self) -> str:
        return self._title

    @title.setter
    def title(self, value: str):
        self._title = value

    @property
    def price(self) -> float:
        return self._price

    @price.setter
    def price(self, value: float):
        if not isinstance(value, (int, float)):
            raise TypeError("Price must be a number")
        self._price = value

    def __str__(self):
        return f"Book(title={self.title}, price={self.price})"

    def __eq__(self, other):
        if not isinstance(other, Book):
            return False
        return (self.title == other.title) and (self.price == other.price)

    def __hash__(self):
        return hash((self.title, self.price))
