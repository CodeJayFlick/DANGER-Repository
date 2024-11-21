Here is the translation of the given Java code into equivalent Python:

```Python
class ObjectiveC1_State:
    def __init__(self, program, monitor):
        self.program = program
        self.pointer_size = program.get_address_factory().get_default_address_space().get_pointer_size()
        self.is_32bit = self.pointer_size * 8 == 32
        self.is_64bit = self.pointer_size * 8 == 64
        self.monitor = monitor

    def dispose(self):
        del self.been_applied[:]
        self.method_map.clear()
        self.thumb_code_locations.clear()

class ObjectiveC1_TypeEncodings:
    def __init__(self, pointer_size, category_path):
        pass

def get_objective_c_section_names():
    return ["section_name_1", "section_name_2"]

# usage
program = None  # replace with your program object
monitor = None  # replace with your monitor object
category_path = None  # replace with your category path object

objective_c_state = ObjectiveC1_State(program, monitor)
print(objective_c_state.get_objective_c_section_names())
```

Please note that Python does not have direct equivalents for Java's `Set`, `Map` and other collections. Instead, you can use built-in data structures like lists or dictionaries.

Also, the `ObjectiveC1_TypeEncodings` class is empty in your code, so I didn't translate it into Python as there seems to be no logic inside this class.