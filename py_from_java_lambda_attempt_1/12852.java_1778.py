Here is the translation of the Java code to Python:
```
class LocationUtil:
    def __init__(self):
        pass  # private constructor

    @staticmethod
    def minimum(locations: list) -> 'Location':
        min_location = None
        for location in locations:
            if min_location is None or (location and location.lineno > min_location.lineno):
                min_location = location
        return min_location

    @staticmethod
    def maximum(locations: list) -> 'Location':
        max_location = None
        for location in locations:
            if max_location is None or (location and location.lineno > max_location.lineno):
                max_location = location
        return max_location


class Location:
    pass  # placeholder, assuming this class exists elsewhere

# Example usage:
locations = [Location(), Location(lineno=2), Location(lineno=1)]
min_loc = LocationUtil.minimum(locations)
max_loc = LocationUtil.maximum(locations)

print(min_loc)  # prints the first location with lineno <= 1
print(max_loc)  # prints the last location with lineno >= 2
```
Note that I assumed `Location` is a separate class defined elsewhere, and only provided a placeholder implementation for it. In Python, classes are not required to have explicit constructors or methods declared as static; instead, you can use the `@staticmethod` decorator to define functions that operate on instances of other classes (in this case, `Location`).