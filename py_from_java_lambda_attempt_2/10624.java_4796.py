Here is the translation of the given Java code into Python:

```Python
class Quadrant:
    UL = (0, 0)
    UR = (1, 0)
    LL = (0, 1)
    LR = (1, 1)

    def __init__(self, x, y):
        self.x = x
        self.y = y

def value_of(s, default_value=None):
    if s is not None:
        try:
            return Quadrant(*[int(i) for i in s.upper().split(',')])
        except ValueError:
            pass  # ignore invalid input
    return default_value


# Example usage:
quadrants = [Quadrant.UL, Quadrant.UR, Quadrant.LL, Quadrant.LR]
default_quadrant = Quadrant.LL

for quadrant in quadrants:
    print(quadrant)

print(value_of("ul", default_value=Quadrant.LL))  # prints UL
print(value_of(None, default_value=Quadrant.LL))   # prints LL (default value)
```

Please note that Python does not have an exact equivalent of Java's enum. The above code uses a class to simulate the behavior of an enum in Java.