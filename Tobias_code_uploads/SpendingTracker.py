# Python Program to Track Monthly Spendings

class SpendingTracker:
    def __init__(self):
        self.expenses = {}

    # Function to add an expense
    def add_expense(self, category, amount):
        if category in self.expenses:
            self.expenses[category] += amount
        else:
            self.expenses[category] = amount
        print(f"Added {amount} to {category} category.")

    # Function to display total spending
    def view_total_spending(self):
        total = sum(self.expenses.values())
        print(f"Total Spending for this month: ${total:.2f}")
        return total

    # Function to display spendings by category
    def view_spending_by_category(self):
        if not self.expenses:
            print("No expenses recorded.")
            return
        print("Spending by Category:")
        for category, amount in self.expenses.items():
            print(f"{category}: ${amount:.2f}")

# Main function to interact with the tracker
def main():
    tracker = SpendingTracker()
    
    while True:
        print("\nMenu:")
        print("1. Add Expense")
        print("2. View Total Spending")
        print("3. View Spending by Category")
        print("4. Exit")
        choice = input("Choose an option (1-4): ")

        if choice == '1':
            category = input("Enter the category (e.g., Groceries, Rent, Entertainment): ")
            amount = float(input(f"Enter the amount spent on {category}: $"))
            tracker.add_expense(category, amount)
        
        elif choice == '2':
            tracker.view_total_spending()

        elif choice == '3':
            tracker.view_spending_by_category()

        elif choice == '4':
            print("Exiting the Spending Tracker. Goodbye!")
            break

        else:
            print("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
