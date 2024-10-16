import pygame
import random
import numpy as np

# Initialize pygame
pygame.init()

# Window dimensions
WIDTH, HEIGHT = 800, 600
window = pygame.display.set_mode((WIDTH, HEIGHT))
pygame.display.set_caption('Traffic Flow Simulator')

# Colors
BLACK = (0, 0, 0)
WHITE = (255, 255, 255)
RED = (255, 0, 0)
GREEN = (0, 255, 0)
YELLOW = (255, 255, 0)

# Road dimensions
ROAD_WIDTH = 40

# Define grid (3x3 intersections)
NUM_ROWS = 3
NUM_COLS = 3
GRID_SIZE = min(WIDTH // (NUM_COLS + 1), HEIGHT // (NUM_ROWS + 1))

# Time variables
clock = pygame.time.Clock()
FPS = 60  # Frames per second

# Traffic light cycle times (in seconds)
GREEN_LIGHT_TIME = 10
YELLOW_LIGHT_TIME = 3
RED_LIGHT_TIME = 10

class TrafficLight:
    def __init__(self, position):
        self.position = position
        self.state = 'RED'
        self.timer = 0

    def update(self, dt):
        self.timer += dt
        if self.state == 'GREEN' and self.timer >= GREEN_LIGHT_TIME * 1000:
            self.state = 'YELLOW'
            self.timer = 0
        elif self.state == 'YELLOW' and self.timer >= YELLOW_LIGHT_TIME * 1000:
            self.state = 'RED'
            self.timer = 0
        elif self.state == 'RED' and self.timer >= RED_LIGHT_TIME * 1000:
            self.state = 'GREEN'
            self.timer = 0

    def draw(self, window):
        color = GREEN if self.state == 'GREEN' else YELLOW if self.state == 'YELLOW' else RED
        pygame.draw.circle(window, color, self.position, 15)

class Vehicle:
    def __init__(self, x, y, direction):
        self.x = x
        self.y = y
        self.direction = direction  # 'horizontal' or 'vertical'
        self.speed = random.randint(2, 5)  # Speed in pixels per frame

    def move(self):
        if self.direction == 'horizontal':
            self.x += self.speed
        elif self.direction == 'vertical':
            self.y += self.speed

    def draw(self, window):
        pygame.draw.rect(window, WHITE, (self.x, self.y, 20, 10))

# Create traffic lights at intersections
traffic_lights = []
for row in range(1, NUM_ROWS + 1):
    for col in range(1, NUM_COLS + 1):
        x = col * GRID_SIZE
        y = row * GRID_SIZE
        traffic_lights.append(TrafficLight((x, y)))

# Create a list of vehicles
vehicles = [Vehicle(0, GRID_SIZE * 2, 'horizontal') for _ in range(5)]


def main():
    run = True
    while run:
        dt = clock.tick(FPS)  # Time passed since last frame (ms)
        window.fill(BLACK)

        # Event handling
        for event in pygame.event.get():
            if event.type == pygame.QUIT:
                run = False

        # Update traffic lights
        for light in traffic_lights:
            light.update(dt)
            light.draw(window)

        # Move and draw vehicles
        for vehicle in vehicles:
            vehicle.move()
            vehicle.draw(window)

        pygame.display.update()

    pygame.quit()


if __name__ == "__main__":
    main()

def optimize_traffic_lights(vehicles, traffic_lights):
    # Count vehicles approaching each traffic light
    light_vehicle_count = [0] * len(traffic_lights)

    for vehicle in vehicles:
        for i, light in enumerate(traffic_lights):
            if vehicle.direction == 'horizontal' and abs(vehicle.y - light.position[1]) < 20:
                light_vehicle_count[i] += 1
            elif vehicle.direction == 'vertical' and abs(vehicle.x - light.position[0]) < 20:
                light_vehicle_count[i] += 1

    # Adjust green light times based on traffic
    for i, light in enumerate(traffic_lights):
        if light_vehicle_count[i] > 3:  # If there are more than 3 vehicles, extend green time
            light.timer = max(light.timer, GREEN_LIGHT_TIME * 1.5)
        elif light_vehicle_count[i] < 2:  # Fewer vehicles, shorten green time
            light.timer = max(light.timer, GREEN_LIGHT_TIME * 0.8)


# Call this function in the main loop before updating traffic lights
optimize_traffic_lights(vehicles, traffic_lights)