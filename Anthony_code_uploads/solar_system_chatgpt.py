import turtle
import math
import random

# Setup screen
screen = turtle.Screen()
screen.bgcolor("black")
screen.title("Enhanced Solar System Simulation")
screen.tracer(0)  # Disable automatic screen updates for smooth animation

# Create a class for celestial objects (Sun, Planets, Moons)
class CelestialObject(turtle.Turtle):
    def __init__(self, distance, size, color, speed, name=""):
        super().__init__()
        self.shape("circle")
        self.color(color)
        self.shapesize(stretch_wid=size, stretch_len=size)
        self.penup()
        self.distance = distance
        self.angle = random.randint(0, 360)
        self.speed = speed
        self.name = name

    def move(self):
        self.angle += self.speed
        x = self.distance * math.cos(math.radians(self.angle))
        y = self.distance * math.sin(math.radians(self.angle))
        self.goto(x, y)

# Sun Class
class Sun(CelestialObject):
    def __init__(self, size, color):
        super().__init__(0, size, color, 0)
        self.goto(0, 0)

# Planet Class
class Planet(CelestialObject):
    def __init__(self, distance, size, color, speed):
        super().__init__(distance, size, color, speed)
        self.moons = []

    def add_moon(self, moon):
        self.moons.append(moon)

    def move(self):
        super().move()
        for moon in self.moons:
            moon.move_around(self)

# Moon Class (Orbits around a planet)
class Moon(CelestialObject):
    def __init__(self, distance, size, color, speed):
        super().__init__(distance, size, color, speed)

    def move_around(self, planet):
        self.angle += self.speed
        x = planet.xcor() + self.distance * math.cos(math.radians(self.angle))
        y = planet.ycor() + self.distance * math.sin(math.radians(self.angle))
        self.goto(x, y)

# Create Solar System
class SolarSystem:
    def __init__(self):
        self.sun = Sun(2, "yellow")
        self.planets = []
        self.speed_factor = 1.0  # Speed control

    def add_planet(self, planet):
        self.planets.append(planet)

    def move_all(self):
        for planet in self.planets:
            planet.move()

    def adjust_speed(self, factor):
        for planet in self.planets:
            planet.speed *= factor
            for moon in planet.moons:
                moon.speed *= factor

# Create background stars
def create_stars():
    stars = turtle.Turtle()
    stars.hideturtle()
    stars.penup()
    stars.speed(0)
    stars.color("white")
    for _ in range(100):
        x = random.randint(-400, 400)
        y = random.randint(-400, 400)
        stars.goto(x, y)
        stars.dot(random.randint(1, 3))  # Vary the star sizes

# Add planets and moons with random attributes
def generate_random_planet_system(solar_system):
    planet_colors = ["blue", "red", "green", "orange", "purple", "pink", "cyan"]
    
    for _ in range(5):  # Generate 5 random planets
        distance = random.randint(50, 250)
        size = random.uniform(0.4, 1.2)
        color = random.choice(planet_colors)
        speed = random.uniform(0.1, 0.8)

        planet = Planet(distance, size, color, speed)
        
        # Randomly add moons to the planet
        if random.random() > 0.5:  # 50% chance to have moons
            num_moons = random.randint(1, 3)
            for _ in range(num_moons):
                moon_distance = random.randint(10, 30)
                moon_size = random.uniform(0.1, 0.3)
                moon_color = random.choice(planet_colors)
                moon_speed = random.uniform(0.5, 1.5)
                moon = Moon(moon_distance, moon_size, moon_color, moon_speed)
                planet.add_moon(moon)

        solar_system.add_planet(planet)

# Keyboard control for speeding up/down
def speed_up():
    solar_system.adjust_speed(1.2)

def speed_down():
    solar_system.adjust_speed(0.8)

# Collision detection (moon hits the planet)
def detect_collision(planet):
    for moon in planet.moons:
        if moon.distance <= 5:  # Simple threshold for collision
            moon.color("red")  # Change color to indicate collision
            return True
    return False

# Create solar system and random planets
solar_system = SolarSystem()
create_stars()
generate_random_planet_system(solar_system)

# Set up keyboard bindings
screen.listen()
screen.onkey(speed_up, "Up")
screen.onkey(speed_down, "Down")

# Animation loop
while True:
    solar_system.move_all()
    
    # Check for collisions
    for planet in solar_system.planets:
        if detect_collision(planet):
            print(f"Collision detected with planet at distance {planet.distance}")
    
    screen.update()
