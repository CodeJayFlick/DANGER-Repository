Here is the translation of the Java code to Python:
```
import os
from collections import defaultdict

class ModuleDefinitionsMap:
    _module_map = None

    @classmethod
    def get_module_map(cls):
        if cls._module_map is None:
            module_root_directories = Application.get_module_root_directories()
            cls._module_map = defaultdict(dict)
            for resource_file in module_root_directories:
                cls._module_map[resource_file.name] = os.path.abspath(resource_file.path)
        return dict(cls._module_map)

class Application:
    @classmethod
    def get_module_root_directories(cls):
        # implement this method to return a list of directories
        pass

# Example usage:
if __name__ == '__main__':
    module_definitions_map = ModuleDefinitionsMap()
    print(module_definitions_map.get_module_map())
```
Note that I had to make some assumptions about the `Application` class and its methods, as they were not provided in the original Java code. You will need to implement these methods yourself depending on your specific use case.

Also, Python does not have a direct equivalent of Java's `HashMap`, so I used the built-in dictionary type (`dict`) with some additional logic to mimic the behavior of the Java code.