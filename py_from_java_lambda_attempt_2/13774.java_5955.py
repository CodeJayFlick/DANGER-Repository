Here is the translation of the Java code to Python:

```Python
class Cash:
    def __init__(self):
        self.amount = 0

    # plus
    def add(self, amount: int) -> None:
        self.amount += amount

    # minus
    def subtract(self, amount: int) -> bool:
        if self.amount >= amount:
            self.amount -= amount
            return True
        else:
            return False

    # count
    def get_amount(self) -> int:
        return self.amount


# Example usage:
cash = Cash()
print(cash.get_amount())  # Output: 0

cash.add(10)
print(cash.get_amount())  # Output: 10

cash.subtract(5)
print(cash.get_amount())  # Output: 5
```

Note that Python does not have a direct equivalent to Java's `@AllArgsConstructor` annotation, which is used to automatically generate constructors. In this translation, I've simply defined an empty constructor (`__init__`) and initialized the `amount` attribute within it.