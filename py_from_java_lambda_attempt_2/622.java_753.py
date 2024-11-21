Here's your Java code translated into Python:

```Python
class DbgListKernelMemoryRegionsCommand:
    def __init__(self):
        self.memory_regions = []

    def complete(self, pending=None):
        return self.memory_regions

    def invoke(self):
        section1 = {
            "name": "lomem",
            "start": 0,
            "end": 2**63 - 1,
            "allocation_base": 0,
            "protection": ["R", "W", "X"],
            "state": "COMMIT",
            "type": "NONE"
        }
        section = DbgModuleMemory(**section1)
        self.memory_regions.append(section)

        section2 = {
            "name": "himem",
            "start": 0x8000000000000000,
            "end": 0xFFFFFFFFFFFFFFFF,
            "allocation_base": 0x8000000000000000,
            "protection": ["R", "W", "X"],
            "state": "COMMIT",
            "type": "NONE"
        }
        section = DbgModuleMemory(**section2)
        self.memory_regions.append(section)


class DbgModuleMemory:
    def __init__(self, name, start, end, allocation_base, protection, state, type):
        self.name = name
        self.start = start
        self.end = end
        self.allocation_base = allocation_base
        self.protection = protection
        self.state = state
        self.type = type


# Example usage:
command = DbgListKernelMemoryRegionsCommand()
print(command.complete())  # prints the list of memory regions
```

Please note that this is a simplified translation and might not exactly match your original Java code.