class Rect:
    def __init__(self, x: float, y: float, width: float, height: float):
        self.coordinate_x = x
        self.coordinate_y = y
        self.width = width
        self.height = height

    def contains(self, p) -> bool:
        return (p.x >= self.coordinate_x - self.width / 2 and 
                p.x <= self.coordinate_x + self.width / 2 and 
                p.y >= self.coordinate_y - self.height / 2 and 
                p.y <= self.coordinate_y + self.height / 2)

    def intersects(self, other: 'Rect') -> bool:
        return not (self.coordinate_x + self.width / 2 <= other.coordinate_x - other.width / 2 or
                    self.coordinate_x - self.width / 2 >= other.coordinate_x + other.width / 2 or
                    self.coordinate_y + self.height / 2 <= other.coordinate_y - other.height / 2 or
                    self.coordinate_y - self.height / 2 >= other.coordinate_y + other.height / 2)
