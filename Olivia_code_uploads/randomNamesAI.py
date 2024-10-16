import random

# List of names (you can modify this list with actual names for the play)
names = ["Alice", "Bob", "Charlie", "Diana", "Evelyn", "Frank", "Grace", "Henry", "Ivy", "Jack"]

# Ask the user how many names to select
num_to_select = int(input("How many people would you like to select for the play? "))

# Ensure the number to select is not greater than the list size
if num_to_select > len(names):
    print("You cannot select more people than available in the list.")
else:
    # Randomly select names
    selected_names = random.sample(names, num_to_select)
    
    # Print selected names
    print("\nThe following people have been selected for the play:")
    for name in selected_names:
        print(name)