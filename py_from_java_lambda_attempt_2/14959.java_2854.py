Here is the translation of the given Java code into Python:

```Python
import random
from collections import defaultdict

class Bubble:
    def __init__(self, x: int, y: int, id: int, radius: int):
        self.x = x
        self.y = y
        self.id = id
        self.radius = radius

    def move(self):
        self.x += random.randint(-1, 1)
        self.y += random.randint(-1, 1)

    @staticmethod
    def distance(bubble1: 'Bubble', bubble2: 'Bubble') -> float:
        return ((bubble1.x - bubble2.x) ** 2 + (bubble1.y - bubble2.y) ** 2) ** 0.5

    def touches(self, other: 'Bubble') -> bool:
        return self.distance(self, other) <= self.radius + other.radius

    def pop(self):
        print(f"Pop! Bubble {self.id} at ({self.x}, {self.y})")

    def handle_collision(self, bubbles: dict[int, 'Bubble']):
        to_be_popped = False
        for bubble in bubbles.values():
            if bubble != self and self.touches(bubble):
                bubble.pop()
                to_be_popped = True

        if to_be_popped:
            self.pop()

# Example usage:

bubbles = defaultdict(Bubble)
for i in range(5):
    x, y = random.randint(-100, 100), random.randint(-100, 100)
    bubbles[i] = Bubble(x, y, i, 10)

while True:
    for bubble in list(bubbles.values()):
        bubble.move()
        if not bubble.touches():
            continue
        handle_collision({k: v for k, v in bubbles.items()})
```

Please note that Python does not have a direct equivalent to Java's `@Slf4j` annotation. The logging functionality is implemented using the built-in `print()` function in this translation.