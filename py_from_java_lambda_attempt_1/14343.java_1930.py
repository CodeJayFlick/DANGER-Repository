Here is the translation of the Java interface `WireTransfers` into a Python class:

```python
class WireTransfers:
    def set_funds(self, bank_account: str, amount: int) -> None:
        pass  # implement this method in your subclass

    def get_funds(self, bank_account: str) -> int:
        raise NotImplementedError("get_funds must be implemented by a subclass")

    def transfer_funds(self, amount: int, source_bank_account: str, destination_bank_account: str) -> bool:
        raise NotImplementedError("transfer_funds must be implemented by a subclass")
```

Note that in Python, we don't have an equivalent to Java's `interface` keyword. Instead, we define a class with abstract methods (i.e., methods without implementation). The `pass` statement is used as a placeholder for the method body until it's implemented in a subclass.

Also, I've kept the same method names and signatures as the original Java interface, but note that Python uses snake_case naming conventions instead of camelCase.