Here is the translation of the given Java code into Python:

```Python
import random
from collections import defaultdict

class Point:
    def __init__(self, x, y, id):
        self.x = x
        self.y = y
        self.id = id


class Bubble(Point):
    pass


class Rect:
    def __init__(self, left, top, right, bottom):
        self.left = left
        self.top = top
        self.right = right
        self.bottom = bottom

    def contains(self, point):
        return (point.x >= self.left and point.x <= self.right) and \
               (point.y >= self.top and point.y <= self.bottom)


class QuadTree:
    def __init__(self, rect, capacity=4):
        self.rect = rect
        self.capacity = capacity
        self.points = defaultdict(list)
        self.divided = False

    def insert(self, point):
        if not self.rect.contains(point):
            return None
        if len(self.points) < self.capacity:
            self.points[point.id].append(point)
        else:
            if not self.divided:
                self.subdivide()
            xmid = (self.rect.left + self.rect.right) // 2
            ymid = (self.rect.top + self.rect.bottom) // 2

            top_left = Rect(self.rect.left, self.rect.top, xmid, ymid)
            top_right = Rect(xmid, self.rect.top, self.rect.right, ymid)
            bottom_left = Rect(self.rect.left, ymid, xmid, self.rect.bottom)
            bottom_right = Rect(xmid, ymid, self.rect.right, self.rect.bottom)

            for p in point:
                if top_left.contains(p):
                    self.points[0].append(p)
                elif top_right.contains(p):
                    self.points[1].append(p)
                elif bottom_left.contains(p):
                    self.points[2].append(p)
                else:
                    self.points[3].append(p)

    def subdivide(self):
        xmid = (self.rect.left + self.rect.right) // 2
        ymid = (self.rect.top + self.rect.bottom) // 2

        top_left = Rect(self.rect.left, self.rect.top, xmid, ymid)
        top_right = Rect(xmid, self.rect.top, self.rect.right, ymid)
        bottom_left = Rect(self.rect.left, ymid, xmid, self.rect.bottom)
        bottom_right = Rect(xmid, ymid, self.rect.right, self.rect.bottom)

        self.points[0] = QuadTree(top_left)
        self.points[1] = QuadTree(top_right)
        self.points[2] = QuadTree(bottom_left)
        self.points[3] = QuadTree(bottom_right)

    def query(self, rect):
        result = []
        for p in self.points:
            if isinstance(p, dict):
                for point_id in p:
                    for point in p[point_id]:
                        if rect.contains(point):
                            result.append(point)
            else:
                for point in p.points:
                    if rect.contains(point):
                        result.append(point)

        return result


def query_test():
    points = []
    rand = random.Random()
    for i in range(20):
        x, y = rand.randint(0, 300), rand.randint(0, 300)
        p = Bubble(x, y, i, rand.randint(1, 2))
        points.append(p)

    field_rect = Rect(150, 150, 300, 300)  # size of field
    query_range = Rect(70, 130, 100, 100)  # result = all points lying in this rectangle

    # points found in the query range using quadtree and normal method is same
    q_tree_points = QuadTreeTest.query_test(points, field_rect, query_range)
    verify_points = QuadTreeTest.verify(points, query_range)

    assert set(q_tree_points) == set(verify_points)


def main():
    query_test()


if __name__ == "__main__":
    main()
```

This Python code is a direct translation of the given Java code. The `QuadTree` class in this code has similar functionality as its counterpart in the original Java code, but it does not include some details like error handling and edge cases that were present in the original code.