class BillingSystem:
    def __init__(self):
        self.items = []  # List to store item details
        self.discount = 0  # Default discount
        self.tax = 0  # Default tax percentage

    def add_item(self, name, price, quantity):
        """
        Adds an item to the billing system.
        """
        item = {
            'name': name,
            'price': price,
            'quantity': quantity,
            'total': price * quantity
        }
        self.items.append(item)
        print(f"Added {quantity} x {name} @ {price} each. Total: {item['total']}")

    def remove_item(self, name):
        """
        Removes an item from the bill by its name.
        """
        for item in self.items:
            if item['name'] == name:
                self.items.remove(item)
                print(f"Removed {name} from the bill.")
                return
        print(f"Item '{name}' not found in the bill.")

    def apply_discount(self, discount_percentage):
        """
        Applies a discount to the total bill.
        """
        self.discount = discount_percentage
        print(f"Discount of {discount_percentage}% applied.")

    def apply_tax(self, tax_percentage):
        """
        Adds a tax percentage to the total bill.
        """
        self.tax = tax_percentage
        print(f"Tax of {tax_percentage}% applied.")

    def display_items(self):
        """
        Displays all items with their prices, quantities, and totals.
        """
        if not self.items:
            print("No items have been added.")
            return
        
        print("\n--- Items in Bill ---")
        for i, item in enumerate(self.items, start=1):
            print(f"{i}. {item['name']} - {item['quantity']} x {item['price']} = {item['total']}")

    def calculate_total(self):
        """
        Calculates the total amount spent, including discounts and tax.
        """
        total_spending = sum(item['total'] for item in self.items)
        
        # Apply discount
        if self.discount:
            discount_amount = total_spending * (self.discount / 100)
            total_spending -= discount_amount
            print(f"Discount: -{discount_amount}")

        # Apply tax
        if self.tax:
            tax_amount = total_spending * (self.tax / 100)
            total_spending += tax_amount
            print(f"Tax: +{tax_amount}")

        print(f"\nTotal Spending after Discount and Tax: {total_spending}")
        return total_spending

    def clear_bill(self):
        """
        Clears all items from the bill.
        """
        self.items.clear()
        print("Bill has been cleared.")

# Example usage
if __name__ == "__main__":
    billing = BillingSystem()

    # Adding items
    billing.add_item("Laptop", 1000, 2)
    billing.add_item("Mouse", 25, 3)
    billing.add_item("Keyboard", 50, 1)

    # Display items
    billing.display_items()

    # Apply discount and tax
    billing.apply_discount(10)  # 10% discount
    billing.apply_tax(5)  # 5% tax

    # Calculate total spending
    billing.calculate_total()

    # Remove an item
    billing.remove_item("Mouse")
    billing.display_items()

    # Clear the bill
    billing.clear_bill()
