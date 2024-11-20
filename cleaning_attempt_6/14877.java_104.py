class ForeignTaxCalculator:
    """Tax calculator for foreign goods with a tax rate of 60%"""
    
    TAX_PERCENTAGE = 0.6
    
    def calculate(self, amount):
        return amount * self.TAX_PERCENTAGE / 100.0

# Example usage:
tax_calculator = ForeignTaxCalculator()
amount = 100
print(tax_calculator.calculate(amount))  # Output: 60.0
