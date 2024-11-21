Here is the translation of the given Java code into equivalent Python:

```Python
class LldbListMemoryRegionsCommand:
    def __init__(self, manager, process):
        self.manager = manager
        self.process = process
        self.memory_regions = []

    def complete(self, pending=None):
        return self.memory_regions

    def invoke(self):
        regions = self.process.get_memory_regions()
        for i in range(regions.size()):
            info = SBMemoryRegionInfo()  # Assuming this is a Python class or object that can be instantiated
            success = regions.get_memory_region_at_index(i, info)
            if success:
                self.memory_regions.append(info)

class SBProcess:
    def get_memory_regions(self):
        pass

class SBMemoryRegionInfo:
    pass
```

Please note that the above code is a direct translation of your Java code into Python. However, it assumes some classes (`SBProcess`, `SBMemoryRegionInfo`) which are not defined in this snippet and would need to be implemented separately.

Also, please remember that Python does not have an exact equivalent for Java's List class (which you're using here). Instead, you can use built-in list type or any other collection types like set, tuple etc.