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
