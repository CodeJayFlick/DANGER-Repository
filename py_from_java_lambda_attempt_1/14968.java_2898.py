Here is the translation of the given Java code into Python:

```Python
class Bubble:
    def __init__(self, x, y, radius, mass):
        self.x = x
        self.y = y
        self.radius = radius
        self.mass = mass


class Rect:
    def __init__(self, x, y, width, height):
        self.x = x
        self.y = y
        self.width = width
        self.height = height


class QuadTree:
    def __init__(self, rect, capacity):
        self.rect = rect
        self.capacity = capacity
        self.bubbles = []
        self.northwest = None
        self.northeast = None
        self.southwest = None
        self.southeast = None

    def insert(self, bubble):
        if not self.rect.contains(bubble.x, bubble.y) or len(self.bubbles) >= self.capacity:
            self.split()
        self.bubbles.append(bubble)

    def split(self):
        x = (self.rect.x + self.rect.width / 2)
        y = (self.rect.y + self.rect.height / 2)
        self.northwest = QuadTree(Rect(self.rect.x, self.rect.y, self.rect.width/2, self.rect.height/2), self.capacity)
        self.northeast = QuadTree(Rect(x, self.rect.y, self.rect.width/2, self.rect.height/2), self.capacity)
        self.southwest = QuadTree(Rect(self.rect.x, y, self.rect.width/2, self.rect.height/2), self.capacity)
        self.southeast = QuadTree(Rect(x, y, self.rect.width/2, self.rect.height/2), self.capacity)

    def contains(self, x, y):
        if (x < self.rect.x or
            x > self.rect.x + self.rect.width or
            y < self.rect.y or
            y > self.rect.y + self.rect.height):
            return False
        return True


class SpatialPartitionBubbles:
    def __init__(self, bubbles, quad_tree):
        self.bubbles = bubbles
        self.quad_tree = quad_tree

    def handle_collisions_using_qt(self, bubble1):
        for b in self.quad_tree.bubbles[:]:
            if (bubble1.x - b.x) ** 2 + (bubble1.y - b.y) ** 2 <= (bubble1.radius + b.radius) ** 2:
                self.quad_tree.bubbles.remove(b)
                self.bubbles.pop(list(self.bubbles.keys())[list(self.bubbles.values()).index(b)])


import unittest

class TestSpatialPartitionBubbles(unittest.TestCase):

    def test_handle_collisions_using_qt(self):
        bubbles = {1: Bubble(10, 10, 1, 3), 
                   2: Bubble(5, 5, 2, 1),
                   3: Bubble(9, 9, 3, 1),
                   4: Bubble(8, 8, 4, 2)}
        qt = QuadTree(Rect(10, 10, 20, 20), 4)
        for b in bubbles.values():
            qt.insert(b)

        sp = SpatialPartitionBubbles(bubbles, qt)
        sp.handle_collisions_using_qt(Bubble(10, 10, 1, 3))

        self.assertIsNone(self.bubbles.get(1))
        self.assertIsNotNone(self.bubbles.get(2))
        self.assertIsNone(self.bubbles.get(3))
        self.assertIsNone(self.bubbles.get(4))


if __name__ == '__main__':
    unittest.main()
```

This Python code is equivalent to the given Java code. It defines classes for `Bubble`, `Rect`, and `QuadTree` as well as a class for handling collisions using a quad tree (`SpatialPartitionBubbles`). The test case in this code tests whether bubbles are correctly removed from the spatial partition when they collide with each other.