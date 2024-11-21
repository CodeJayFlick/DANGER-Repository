Here is the translation of the given Java code into Python:

```Python
class BlockSphereIterator:
    def __init__(self, center: tuple, radius: float):
        self.center = center
        self.radius_squared = radius ** 2 * 1e-6  # equivalent to Skript. EPSILON_MULT

    def check(self, block) -> bool:
        if block is None or not isinstance(block.get_location(), tuple):
            return False
        
        x_diff = (block.get_location()[0] - self.center[0]) ** 2
        y_diff = (block.get_location()[1] - self.center[1]) ** 2
        z_diff = (block.get_location()[2] - self.center[2]) ** 2

        return x_diff + y_diff + z_diff < self.radius_squared


# Usage:
class Location(tuple):
    pass

class Block:
    def get_location(self) -> tuple:
        return (0, 0, 0)

def main():
    center = (1.5, 3.4, -2)
    radius = 10
    iterator = BlockSphereIterator(center, radius)
    
    # Now you can use the iterator to check blocks within a certain sphere.
    for block in [Block()]:  # Replace with actual data or loop.
        if iterator.check(block):
            print(f"Found block at {block.get_location()}")

if __name__ == "__main__":
    main()
```

Please note that Python does not have direct equivalent of Java's `@Nullable` annotation. Instead, we can use the fact that in Python, `None` is a special value indicating the absence of an object.