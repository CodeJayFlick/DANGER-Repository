Here is the translation of the given Java code into equivalent Python:

```Python
class FcgLevel:
    def __init__(self, distance: int, direction):
        self.row = 1 + distance if direction == "OUT" else -distance
        if self.row == 0:
            raise ValueError("The FcgLevel uses a 1-based row system")
        if self.row == 1 and direction != "IN_AND_OUT":
            raise ValueError("Row 1 must be IN_AND_OUT")

    @staticmethod
    def source_level():
        return FcgLevel(0, "IN_AND_OUT")

    def get_row(self):
        return self.row

    def get_distance(self):
        return abs(self.row) - 1

    def is_source(self):
        return self.direction == "IN_AND_OUT"

    def parent(self):
        if self.direction != "IN_AND_OUT":
            new_direction = self.direction
            new_distance = self.get_distance() - 1
            if new_distance == 0:
                new_direction = "IN_AND_OUT"
            return FcgLevel(new_distance, new_direction)
        else:
            raise ValueError("To get the parent of the source level you must use the constructor directly")

    def child(self):
        if self.direction != "IN_AND_OUT":
            return FcgLevel(self.get_distance() + 1, self.direction)
        else:
            raise ValueError("To get the child of the source level you must use the constructor directly")

    def is_parent_of(self, other: 'FcgLevel'):
        if self.is_source():
            return other.get_distance() == 1
        elif self.direction != other.direction:
            return False
        else:
            return other.get_distance() - self.get_distance() == 1

    def is_child_of(self, other: 'FcgLevel'):
        return other.is_parent_of(self)

    def child_(self):
        if self.direction != "IN_AND_OUT":
            new_direction = self.direction
            new_distance = self.get_distance() + 1
            return FcgLevel(new_distance, new_direction)
        else:
            raise ValueError("Direction cannot be IN_AND_OUT")

    def __str__(self):
        return f"{self.direction} - row {abs(self.row)}"

    def __eq__(self, other: 'FcgLevel'):
        if self is other:
            return True
        elif not isinstance(other, FcgLevel):
            return False
        else:
            return self.direction == other.direction and self.row == other.row

    def __lt__(self, other: 'FcgLevel'):
        if self.direction != other.direction:
            return self.direction < other.direction
        else:
            return -abs(self.row) + 1 < abs(other.row) - 1

    def get_relative_row(self):
        return -self.row if self.direction == "OUT" else self.row
```

Note: The `compareTo` method in Java is equivalent to the `<` operator and the `equals` method is equivalent to the `==` operator.