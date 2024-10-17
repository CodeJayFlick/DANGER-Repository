# Function to calculate compound interest
def calculate_compound_interest(principal, rate, times_compounded, years):
    # Compound interest formula: A = P * (1 + r/n)^(nt)
    amount = principal * (1 + rate / times_compounded) ** (times_compounded * years)
    return amount

# Get user input
principal = float(input("Enter the principal amount: "))
rate = float(input("Enter the annual interest rate (in %): ")) / 100
times_compounded = int(input("Enter the number of times interest is compounded per year: "))
years = int(input("Enter the number of years the money is invested or borrowed for: "))

# Calculate compound interest
final_amount = calculate_compound_interest(principal, rate, times_compounded, years)
compound_interest = final_amount - principal

# Display results
print(f"\nThe compound interest is: ${compound_interest:.2f}")
print(f"The total amount after {years} years is: ${final_amount:.2f}")
