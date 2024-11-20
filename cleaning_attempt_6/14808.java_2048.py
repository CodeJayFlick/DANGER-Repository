class Customer:
    def __init__(self, id: str, name: str):
        self.id = id
        self.name = name

    @property
    def id(self) -> str:
        return self._id

    @property
    def name(self) -> str:
        return self._name

    def __str__(self) -> str:
        return f"Customer{{'id':'{self.id}'}}"

# Example usage:

customer = Customer("123", "John Doe")
print(customer)
