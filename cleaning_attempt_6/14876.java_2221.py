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
