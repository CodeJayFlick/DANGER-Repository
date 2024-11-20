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
