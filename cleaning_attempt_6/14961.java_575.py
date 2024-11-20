class QuadTree:
    def __init__(self, boundary, capacity):
        self.boundary = boundary
        self.capacity = capacity
        self.divided = False
        self.points = {}
        self.northwest = None
        self.northeast = None
        self.southwest = None
        self.southeast = None

    def insert(self, p):
        if self.boundary.contains(p):
            if len(self.points) < self.capacity:
                self.points[p.id] = p
            else:
                if not self.divided:
                    self.divide()
                if self.northwest and self.northwest.boundary.contains(p):
                    self.northwest.insert(p)
                elif self.northeast and self.northeast.boundary.contains(p):
                    self.northeast.insert(p)
                elif self.southwest and self.southwest.boundary.contains(p):
                    self.southwest.insert(p)
                elif self.southeast and self.southeast.boundary.contains(p):
                    self.southeast.insert(p)

    def divide(self):
        x = self.boundary.x
        y = self.boundary.y
        width = self.boundary.width
        height = self.boundary.height
        nw = Rect(x - width / 4, y + height / 4, width / 2, height / 2)
        self.northwest = QuadTree(nw, self.capacity)
        ne = Rect(x + width / 4, y + height / 4, width / 2, height / 2)
        self.northeast = QuadTree(ne, self.capacity)
        sw = Rect(x - width / 4, y - height / 4, width / 2, height / 2)
        self.southwest = QuadTree(sw, self.capacity)
        se = Rect(x + width / 4, y - height / 4, width / 2, height / 2)
        self.southeast = QuadTree(se, self.capacity)
        self.divided = True

    def query(self, r):
        if self.boundary.intersects(r):
            for p in list(self.points.values()):
                if r.contains(p):
                    yield p
            if self.divided:
                yield from self.northwest.query(r)
                yield from self.northeast.query(r)
                yield from self.southwest.query(r)
                yield from self.southeast.query(r)

class Rect:
    def __init__(self, x, y, width, height):
        self.x = x
        self.y = y
        self.width = width
        self.height = height

    def contains(self, p):
        return (p.x >= self.x and p.x <= self.x + self.width) and \
               (p.y >= self.y and p.y <= self.y + self.height)

    def intersects(self, r):
        return not ((self.x + self.width < r.x or
                     self.x > r.x + r.width or
                     self.y + self.height < r.y or
                     self.y > r.y + r.height))

class Point:
    def __init__(self, id, x, y):
        self.id = id
        self.x = x
        self.y = y

    @property
    def boundary(self):
        return Rect(0, 0, 1, 1)

    def contains(self, r):
        return (self.x >= r.x and self.x <= r.x + r.width) and \
               (self.y >= r.y and self.y <= r.y + r.height)
