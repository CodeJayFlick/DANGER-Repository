Here is the translation of the Java code to Python:

```Python
class DomesticTaxCalculator:
    """Tax Calculator for domestic goods with a tax rate of 20%."""
    
    TAX_PERCENTAGE = 0.2
    
    def calculate(self, amount):
        return amount * self.TAX_PERCENTAGE


# Example usage:
calculator = DomesticTaxCalculator()
amount = 100.00
tax_amount = calculator.calculate(amount)
print(f"Tax: ${tax_amount:.2f}")
```

Note that Python does not have a direct equivalent to Java's `package` statement, so I did not include one in the translation. Also, Python uses indentation instead of curly braces for block-level structure, which is why you see more whitespace than in the original code.