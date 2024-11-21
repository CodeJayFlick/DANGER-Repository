Here is the equivalent Python code:

```Python
class SaveablePoint:
    def __init__(self):
        pass
    
    def __init__(self, point):
        self.point = point
    
    @property
    def point(self):
        return self._point
    
    @point.setter
    def point(self, value):
        if isinstance(value, tuple) and len(value) == 2:
            x, y = value
            if isinstance(x, (int, float)) and isinstance(y, (int, float)):
                self._point = Point(int(x), int(y))
            else:
                raise ValueError("Point must be a tuple of two integers")
        else:
            raise ValueError("Invalid point format")

    def get_point(self):
        return self.point
    
    def restore(self, obj_storage):
        x = obj_storage.get_int()
        y = obj_storage.get_int()
        self.point = Point(x, y)
    
    def save(self, obj_storage):
        obj_storage.put_int(int(self.point.x))
        obj_storage.put_int(int(self.point.y))

    def __eq__(self, other):
        if not isinstance(other, SaveablePoint):
            return False
        return self.point == other.point
    
    def __hash__(self):
        return hash(self.point)
    
    def __str__(self):
        return str(self.point)

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __eq__(self, other):
        if not isinstance(other, Point):
            return False
        return (self.x == other.x) and (self.y == other.y)
    
    def __hash__(self):
        return hash((self.x, self.y))
    
    def __str__(self):
        return f"({self.x}, {self.y})"
```

Note that Python does not have direct equivalent of Java's `ObjectStorage` class. I've replaced it with simple getter and setter methods for the point coordinates in this example.