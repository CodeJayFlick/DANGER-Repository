Here is the translation of the given Java code into equivalent Python:

```Python
class TraceOverlappedRegionException(Exception):
    def __init__(self, conflicts):
        super().__init__("Overlaps other regions")
        self.conflicts = conflicts


from collections import Collection  # Assuming this is a custom class in your project

# Alternatively, you can use the built-in set or list data structure
class TraceMemoryRegion:
    pass

def main():
    conflicts = [TraceMemoryRegion(), TraceMemoryRegion()]
    try:
        raise TraceOverlappedRegionException(conflicts)
    except TraceOverlappedRegionException as e:
        print(f"Error: {e}")
        for conflict in e.conflicts:
            print(f"Conflict region: {conflict}")

if __name__ == "__main__":
    main()
```

Please note that Python does not have direct equivalent of Java's `Collection` class. We can use built-in data structures like list or set, depending on the requirement. In this example, I've used a custom `TraceMemoryRegion` class for simplicity.