# Grocery store aisles and items
aisles = {
    "Aisle 1": {
        "Produce": {"Apples": 0.50, "Bananas": 0.30, "Carrots": 0.25, "Lettuce": 0.60, "Tomatoes": 0.40},
        "Dairy": {"Milk": 1.20, "Cheese": 2.50, "Yogurt": 0.90, "Butter": 1.50, "Cream": 1.75},
        "Beverage": {"Water": 1.00, "Juice": 1.50, "Soda": 1.25, "Coffee": 3.00, "Tea": 2.50},
        "Frozen": {"Pizza": 5.00, "Ice Cream": 3.00, "Peas": 1.00, "Burrito": 2.00, "Fries": 1.75}
    },
    "Aisle 2": {
        "Produce": {"Oranges": 0.50, "Strawberries": 0.70, "Spinach": 0.60, "Peppers": 0.50, "Potatoes": 0.30},
        "Dairy": {"Eggs": 1.50, "Sour Cream": 1.00, "Cottage Cheese": 1.75, "Milk": 1.20, "Cream Cheese": 1.40},
        "Beverage": {"Lemonade": 1.25, "Iced Tea": 1.75, "Smoothie": 2.50, "Energy Drink": 2.75, "Cola": 1.50},
        "Frozen": {"Frozen Pizza": 4.50, "Mixed Veggies": 2.00, "Fish Sticks": 3.00, "Chicken Nuggets": 4.00, "Frozen Yogurt": 3.50}
    },
    "Aisle 3": {
        "Produce": {"Blueberries": 0.75, "Grapes": 0.60, "Cucumber": 0.35, "Onions": 0.25, "Garlic": 0.20},
        "Dairy": {"Almond Milk": 2.00, "Soy Milk": 1.80, "Greek Yogurt": 1.00, "Whipped Cream": 1.30, "Swiss Cheese": 2.75},
        "Beverage": {"Sparkling Water": 1.20, "Hot Chocolate": 2.00, "Apple Juice": 1.80, "Orange Juice": 2.00, "Root Beer": 1.25},
        "Frozen": {"Waffles": 2.50, "Frozen Berries": 3.25, "Corn": 1.50, "Frozen Lasagna": 5.50, "Tater Tots": 2.00}
    },
    "Aisle 4": {
        "Produce": {"Pineapple": 1.00, "Mango": 0.80, "Avocado": 1.20, "Broccoli": 0.40, "Celery": 0.30},
        "Dairy": {"Half & Half": 1.60, "Cottage Cheese": 2.00, "Creamer": 1.50, "Mozzarella": 2.30, "Brie": 3.00},
        "Beverage": {"Sports Drink": 1.80, "Protein Shake": 2.50, "Coconut Water": 2.00, "Ginger Ale": 1.75, "Milkshake": 2.75},
        "Frozen": {"Popsicles": 2.20, "Frozen Bread": 1.90, "Egg Rolls": 3.75, "Frozen Spinach": 1.50, "Frozen Pizza": 4.00}
    }
}

# Function to display items and get user selection
def shop_aisle(aisle):
    selected_items = []
    total_price = 0.0

    print(f"\nYou are now shopping in {aisle}. Here are the items available:")
    for section, items in aisles[aisle].items():
        print(f"\n{section}:")
        for item, price in items.items():
            print(f" - {item}: ${price:.2f}")

    while True:
        choice = input("\nEnter the name of the item you want to purchase (or 'done' to finish): ").strip()
        found = False
        for section, items in aisles[aisle].items():
            if choice in items:
                selected_items.append(choice)
                total_price += items[choice]
                found = True
                print(f"Added {choice} to your cart. Total so far: ${total_price:.2f}")
                break
        if not found:
            if choice.lower() == 'done':
                break
            print("Item not found. Please select a valid item from the list.")

    print("\nYou have finished shopping. Here are the items you purchased:")
    for item in selected_items:
        print(f" - {item}")
    print(f"\nTotal cost: ${total_price:.2f}")

# Main program to select aisle
print("Welcome to the Grocery Store!")
print("Please choose an aisle to shop from:")
for aisle in aisles:
    print(f" - {aisle}")

chosen_aisle = input("\nEnter the aisle you want to shop in: ").strip()
if chosen_aisle in aisles:
    shop_aisle(chosen_aisle)
else:
    print("Invalid aisle selection. Please restart the program and choose a valid aisle.")
