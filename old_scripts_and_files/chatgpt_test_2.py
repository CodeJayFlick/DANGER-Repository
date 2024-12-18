import time
import random
import os

# Clear screen function
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# Print with delay for dramatic effect
def slow_print(text, delay=0.05):
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()

# Map of the game
game_map = {
    "village": {
        "description": "A small peaceful village surrounded by forests.",
        "options": {"forest": "Go to the forest", "shop": "Visit the shop"}
    },
    "forest": {
        "description": "The dense forest is dark and mysterious. You hear strange noises.",
        "options": {"village": "Return to the village", "cave": "Explore the cave"}
    },
    "cave": {
        "description": "The cave is damp and cold. You see faint glimmers of treasure deeper inside.",
        "options": {"forest": "Go back to the forest", "treasure": "Search for treasure"}
    },
    "shop": {
        "description": "A small shop filled with trinkets and supplies.",
        "options": {"village": "Return to the village", "buy": "Buy a healing potion"}
    },
    "treasure": {
        "description": "You find a pile of glittering gold and jewels! But there's a sleeping dragon nearby.",
        "options": {"village": "Escape with the treasure", "fight": "Fight the dragon"}
    }
}

# Inventory system
inventory = {
    "gold": 0,
    "healing_potions": 0,
    "weapon": None
}

# Game variables
current_location = "village"
game_over = False

# Functions for gameplay
def display_location(location):
    clear_screen()
    slow_print(f"You are in: {location.upper()}")
    slow_print(game_map[location]["description"])
    print("\nWhat would you like to do?")
    for key, option in game_map[location]["options"].items():
        print(f"- {key}: {option}")

def handle_shop():
    if inventory["gold"] >= 10:
        inventory["healing_potions"] += 1
        inventory["gold"] -= 10
        slow_print("You bought a healing potion!")
    else:
        slow_print("You don't have enough gold to buy a potion.")

def handle_treasure():
    if random.random() > 0.5:  # 50% chance
        slow_print("You escaped with the treasure!")
        inventory["gold"] += 100
    else:
        slow_print("The dragon wakes up and attacks!")
        handle_combat(dragon=True)

def handle_combat(dragon=False):
    if dragon:
        if inventory["weapon"] == "sword":
            slow_print("You bravely fight the dragon with your sword and win!")
            inventory["gold"] += 200
        else:
            slow_print("You have no weapon to fight the dragon... You are defeated.")
            global game_over
            game_over = True
    else:
        slow_print("You fought off a wild beast in the forest and survived.")

def random_forest_event():
    event = random.choice(["beast", "gold", "nothing"])
    if event == "beast":
        slow_print("A wild beast attacks you!")
        handle_combat()
    elif event == "gold":
        slow_print("You find some gold on the ground.")
        inventory["gold"] += 20
    else:
        slow_print("You wander the forest but nothing happens.")

# Main game loop
def game_loop():
    global current_location, game_over

    while not game_over:
        display_location(current_location)
        options = game_map[current_location]["options"]
        choice = input("\nEnter your choice: ").strip().lower()

        if choice not in options:
            slow_print("Invalid choice. Try again.")
            continue

        if current_location == "shop" and choice == "buy":
            handle_shop()
        elif current_location == "forest" and choice == "cave":
            random_forest_event()
        elif current_location == "treasure" and choice == "fight":
            handle_combat(dragon=True)
        elif current_location == "treasure" and choice == "village":
            handle_treasure()
        else:
            current_location = choice

        if game_over:
            break

    slow_print("Game over! Thanks for playing!")

# Start the game
def start_game():
    clear_screen()
    slow_print("Welcome to the Adventure Game!", delay=0.1)
    slow_print("Your goal is to explore, gather treasures, and survive.\n", delay=0.05)
    slow_print("Type your commands carefully and enjoy the journey.\n", delay=0.05)

    input("Press Enter to start your adventure...")
    game_loop()

if __name__ == "__main__":
    start_game()
