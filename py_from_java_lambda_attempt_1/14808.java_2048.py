Here is the equivalent Python code:

```Python
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
```

Note that Python does not have a direct equivalent to Java's `package` statement. In Python, you can organize your code into modules and packages using the standard library's `__init__.py` files.

Also note that in Python, we use properties (`@property`) instead of getter methods (like `public String getId() { return id; }`).