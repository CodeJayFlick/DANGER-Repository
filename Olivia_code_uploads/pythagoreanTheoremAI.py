import math

def calculate_hypotenuse(a, b):
    return math.sqrt(a**2 + b**2)

def calculate_side(c, other_side):
    return math.sqrt(c**2 - other_side**2)

def main():
    print("Welcome to the Pythagorean Theorem Calculator!")
    while True:
        print("\nWhat would you like to calculate?")
        print("1. Hypotenuse (c)")
        print("2. One of the other sides (a or b)")
        print("3. Exit")
        
        choice = input("Enter your choice (1, 2, or 3): ")

        if choice == '1':
            a = float(input("Enter the length of side a: "))
            b = float(input("Enter the length of side b: "))
            c = calculate_hypotenuse(a, b)
            print(f"The length of the hypotenuse is: {c:.2f}")

        elif choice == '2':
            c = float(input("Enter the length of the hypotenuse (c): "))
            other_side = float(input("Enter the length of the known side (a or b): "))
            
            if c <= other_side:
                print("The hypotenuse must be longer than the other side. Please try again.")
            else:
                missing_side = calculate_side(c, other_side)
                print(f"The length of the missing side is: {missing_side:.2f}")
        
        elif choice == '3':
            print("Goodbye!")
            break
        
        else:
            print("Invalid choice. Please select 1, 2, or 3.")

if __name__ == "__main__":
    main()
