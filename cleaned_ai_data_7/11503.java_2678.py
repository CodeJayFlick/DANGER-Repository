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
