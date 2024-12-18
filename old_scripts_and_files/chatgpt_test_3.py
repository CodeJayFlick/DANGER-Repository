import random
import time
import os

# Dungeon constants
DUNGEON_WIDTH = 40
DUNGEON_HEIGHT = 20
ROOM_COUNT = 6
TREASURE_COUNT = 5

# Symbols for rendering
WALL = "#"
FLOOR = "."
PLAYER = "@"
TREASURE = "T"

# Dungeon map
dungeon = [[WALL for _ in range(DUNGEON_WIDTH)] for _ in range(DUNGEON_HEIGHT)]

# Player state
player_position = [1, 1]
inventory = {"treasures": 0}
game_over = False

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def slow_print(text, delay=0.05):
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()

def initialize_dungeon():
    """Generates a dungeon with rooms and corridors."""
    def carve_room(x, y, w, h):
        for i in range(y, y + h):
            for j in range(x, x + w):
                if 0 < i < DUNGEON_HEIGHT - 1 and 0 < j < DUNGEON_WIDTH - 1:
                    dungeon[i][j] = FLOOR

    def connect_rooms(x1, y1, x2, y2):
        """Carves a corridor between two points."""
        if random.random() > 0.5:  # Horizontal first
            for x in range(min(x1, x2), max(x1, x2) + 1):
                dungeon[y1][x] = FLOOR
            for y in range(min(y1, y2), max(y1, y2) + 1):
                dungeon[y][x2] = FLOOR
        else:  # Vertical first
            for y in range(min(y1, y2), max(y1, y2) + 1):
                dungeon[y][x1] = FLOOR
            for x in range(min(x1, x2), max(x1, x2) + 1):
                dungeon[y2][x] = FLOOR

    rooms = []
    for _ in range(ROOM_COUNT):
        w, h = random.randint(4, 8), random.randint(4, 8)
        x, y = random.randint(1, DUNGEON_WIDTH - w - 1), random.randint(1, DUNGEON_HEIGHT - h - 1)
        rooms.append((x, y, w, h))
        carve_room(x, y, w, h)

    # Connect rooms
    for i in range(len(rooms) - 1):
        x1, y1, _, _ = rooms[i]
        x2, y2, _, _ = rooms[i + 1]
        connect_rooms(x1, y1, x2, y2)

    # Place treasures
    for _ in range(TREASURE_COUNT):
        while True:
            tx, ty = random.randint(1, DUNGEON_WIDTH - 2), random.randint(1, DUNGEON_HEIGHT - 2)
            if dungeon[ty][tx] == FLOOR:
                dungeon[ty][tx] = TREASURE
                break

    # Place player in the first room
    px, py, _, _ = rooms[0]
    player_position[0], player_position[1] = px + 1, py + 1

def render_dungeon():
    """Displays the dungeon."""
    clear_screen()
    for y in range(DUNGEON_HEIGHT):
        for x in range(DUNGEON_WIDTH):
            if [x, y] == player_position:
                print(PLAYER, end="")
            else:
                print(dungeon[y][x], end="")
        print()
    print(f"\nTreasures collected: {inventory['treasures']}/{TREASURE_COUNT}")

def move_player(dx, dy):
    """Moves the player in the dungeon if the path is clear."""
    global game_over
    new_x = player_position[0] + dx
    new_y = player_position[1] + dy

    if dungeon[new_y][new_x] == WALL:
        slow_print("You bump into a wall.")
    elif dungeon[new_y][new_x] == TREASURE:
        inventory["treasures"] += 1
        dungeon[new_y][new_x] = FLOOR
        slow_print("You found a treasure!")
        player_position[0], player_position[1] = new_x, new_y
        if inventory["treasures"] == TREASURE_COUNT:
            slow_print("You collected all treasures! You win!")
            game_over = True
    elif dungeon[new_y][new_x] == FLOOR:
        player_position[0], player_position[1] = new_x, new_y
    else:
        slow_print("You can't move there.")

def game_loop():
    """Main game loop."""
    global game_over
    while not game_over:
        render_dungeon()
        command = input("Move (WASD): ").strip().lower()
        if command == "w":
            move_player(0, -1)
        elif command == "a":
            move_player(-1, 0)
        elif command == "s":
            move_player(0, 1)
        elif command == "d":
            move_player(1, 0)
        else:
            slow_print("Invalid command.")
    slow_print("Game over! Thanks for playing!")

def start_game():
    """Starts the dungeon game."""
    initialize_dungeon()
    render_dungeon()
    slow_print("Welcome to the Dungeon Explorer!")
    slow_print("Your goal is to collect all the treasures.")
    slow_print("Use WASD to move and explore the dungeon.\n")
    input("Press Enter to begin your adventure...")
    game_loop()

if __name__ == "__main__":
    start_game()
