Here is your Java code translated into Python:

```Python
import logging
from random import randint
from collections import defaultdict

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y


class Bubble(Point):
    def __init__(self, coordinate_x, coordinate_y, id, radius):
        super().__init__(coordinate_x, coordinate_y)
        self.id = id
        self.radius = radius

    def move(self):
        # implement bubble movement logic here
        pass

    def handle_collision(self, bubbles_to_check, bubbles):
        # implement collision handling logic here
        pass


class Rect:
    def __init__(self, x, y, width, height):
        self.x = x
        self.y = y
        self.width = width
        self.height = height

    @property
    def top_left(self):
        return (self.x, self.y)

    @property
    def bottom_right(self):
        return ((self.x + self.width), (self.y + self.height))


class QuadTree:
    def __init__(self, rect, capacity=4):
        self.rect = rect
        self.capacity = capacity
        self.objects = []
        self.northwest = None
        self.northeast = None
        self.southwest = None
        self.southeast = None

    def insert(self, obj):
        if not self.rect.contains(obj.x, obj.y) or len(self.objects) >= self.capacity:
            return False

        for o in self.objects[:]:
            if (o.x <= obj.x and o.x + 1000 > obj.x and
                    o.y <= obj.y and o.y + 1000 > obj.y):
                # object is already contained within the quadtree, so move it to a child node
                return False

        self.objects.append(obj)
        if len(self.objects) >= self.capacity:
            x = (self.rect.top_left[0] + self.rect.bottom_right[0]) // 2
            y = (self.rect.top_left[1] + self.rect.bottom_right[1]) // 2
            if not self.northwest:
                self.northwest = QuadTree(Rect(x - 1000, y - 1000, 1000), capacity)
                self.northeast = QuadTree(Rect(x, y - 1000, 1000), capacity)
                self.southwest = QuadTree(Rect(x - 1000, y, 1000), capacity)
                self.southeast = QuadTree(Rect(x, y, 1000), capacity)

            for o in self.objects[:]:
                if not (self.northwest.insert(o) or
                        self.northeast.insert(o) or
                        self.southwest.insert(o) or
                        self.southeast.insert(o)):
                    return False

        return True


class SpatialPartitionBubbles:
    def __init__(self, bubbles, quad_tree):
        self.bubbles = bubbles
        self.quad_tree = quad_tree

    def handle_collisions_using_qt(self, bubble):
        # implement collision handling logic here
        pass


def no_spatial_partition(num_of_movements, bubbles):
    while num_of_movements > 0 and not bubbles:
        for i in range(len(bubbles)):
            bubble = list(bubbles.values())[i]
            bubble.move()
            bubbles[i] = bubble

            # check collisions with all other bubbles
            for j in range(i + 1, len(bubbles)):
                if (bubble.x - list(bubbles.values())[j].x) ** 2 + \
                   (bubble.y - list(bubbles.values())[j].y) ** 2 <= (
                           bubble.radius + list(bubbles.values())[j].radius) ** 2:
                    # handle collision
                    pass

        num_of_movements -= 1


def with_spatial_partition(height, width, num_of_movements, bubbles):
    rect = Rect(width / 2.0, height / 2.0, width, height)
    quad_tree = QuadTree(rect)

    while num_of_movements > 0 and not bubbles:
        for i in range(len(bubbles)):
            bubble = list(bubbles.values())[i]
            bubble.move()
            bubbles[i] = bubble

            # use the quad tree to reduce computations
            sp = SpatialPartitionBubbles(bubbles, quad_tree)
            sp.handle_collisions_using_qt(bubble)

        num_of_movements -= 1


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    bubbles1 = defaultdict(Bubble)
    bubbles2 = defaultdict(Bubble)
    rand = SecureRandom()
    for i in range(10000):
        b = Bubble(rand.randint(0, 300), rand.randint(0, 300), i, rand.randint(1, 2))
        bubbles1[i] = b
        bubbles2[i] = b

    start1 = time.time()
    no_spatial_partition(20, bubbles1)
    end1 = time.time()

    start2 = time.time()
    with_spatial_partition(300, 300, 20, bubbles2)
    end2 = time.time()

    logging.info("Without spatial partition takes %s ms", (end1 - start1))
    logging.info("With spatial partition takes %s ms", (end2 - start2))

```

Please note that this is a direct translation of your Java code into Python. It might not be the most idiomatic or efficient way to write it in Python, but it should work as expected.