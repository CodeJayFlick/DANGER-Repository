import pygame
import time
import random

# Initialize pygame
pygame.init()

# Define colors
WHITE = (255, 255, 255)
BLACK = (0, 0, 0)
RED = (213, 50, 80)
GREEN = (0, 255, 0)
BLUE = (50, 153, 213)

# Set the dimensions of the game window
WIDTH, HEIGHT = 600, 400
game_window = pygame.display.set_mode((WIDTH, HEIGHT))
pygame.display.set_caption('Snake Game')

# Define clock to control the speed of the snake
clock = pygame.time.Clock()

# Define the snake's block size and speed
SNAKE_SIZE = 10
SNAKE_SPEED = 15

# Define fonts
font_style = pygame.font.SysFont("bahnschrift", 25)
score_font = pygame.font.SysFont("comicsansms", 35)

# Function to display the player's score
def display_score(score):
    value = score_font.render(f"Score: {score}", True, BLUE)
    game_window.blit(value, [0, 0])

# Function to draw the snake
def draw_snake(snake_block, snake_list):
    for x in snake_list:
        pygame.draw.rect(game_window, GREEN, [x[0], x[1], snake_block, snake_block])

# Function to display messages on the screen
def display_message(msg, color):
    mesg = font_style.render(msg, True, color)
    game_window.blit(mesg, [WIDTH / 6, HEIGHT / 3])

# Main game loop
def game_loop():
    game_over = False
    game_close = False

    # Starting position of the snake
    x = WIDTH // 2
    y = HEIGHT // 2

    # Track the movement of the snake
    x_change = 0
    y_change = 0

    # List to store the snake's body
    snake_list = []
    length_of_snake = 1

    # Generate random position for the food
    food_x = round(random.randrange(0, WIDTH - SNAKE_SIZE) / 10.0) * 10.0
    food_y = round(random.randrange(0, HEIGHT - SNAKE_SIZE) / 10.0) * 10.0

    while not game_over:

        while game_close:
            game_window.fill(BLACK)
            display_message("Game Over! Press C-Play Again or Q-Quit", RED)
            display_score(length_of_snake - 1)
            pygame.display.update()

            for event in pygame.event.get():
                if event.type == pygame.KEYDOWN:
                    if event.key == pygame.K_q:
                        game_over = True
                        game_close = False
                    if event.key == pygame.K_c:
                        game_loop()

        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                game_over = True
            if event.type == pygame.KEYDOWN:
                if event.key == pygame.K_LEFT:
                    x_change = -SNAKE_SIZE
                    y_change = 0
                elif event.key == pygame.K_RIGHT:
                    x_change = SNAKE_SIZE
                    y_change = 0
                elif event.key == pygame.K_UP:
                    y_change = -SNAKE_SIZE
                    x_change = 0
                elif event.key == pygame.K_DOWN:
                    y_change = SNAKE_SIZE
                    x_change = 0

        # If the snake crosses the boundaries, the game ends
        if x >= WIDTH or x < 0 or y >= HEIGHT or y < 0:
            game_close = True
        x += x_change
        y += y_change

        game_window.fill(BLACK)
        pygame.draw.rect(game_window, RED, [food_x, food_y, SNAKE_SIZE, SNAKE_SIZE])

        snake_head = [x, y]
        snake_list.append(snake_head)
        if len(snake_list) > length_of_snake:
            del snake_list[0]

        # If the snake collides with itself, the game ends
        for block in snake_list[:-1]:
            if block == snake_head:
                game_close = True

        draw_snake(SNAKE_SIZE, snake_list)
        display_score(length_of_snake - 1)

        pygame.display.update()

        # If the snake eats the food
        if x == food_x and y == food_y:
            food_x = round(random.randrange(0, WIDTH - SNAKE_SIZE) / 10.0) * 10.0
            food_y = round(random.randrange(0, HEIGHT - SNAKE_SIZE) / 10.0) * 10.0
            length_of_snake += 1

        clock.tick(SNAKE_SPEED)

    pygame.quit()
    quit()


# Run the game
game_loop()
