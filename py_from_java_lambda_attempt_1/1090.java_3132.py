Here is the equivalent Python code:

```Python
class DbgGetRegisterMapCommand:
    def __init__(self, manager, path):
        self.map = {}
        self.access = manager.get_access()
        self.path = path

    def complete(self, pending=None):
        return self.map

    def invoke(self):
        npath = ["Debugger"]
        npath.extend(self.path)
        attributes = self.access.get_attributes(npath)
        for key in attributes:
            model_object = attributes[key]
            debug_value = self.access.get_debug_value(model_object)
            if debug_value is not None:
                register = {
                    "key": key,
                    "i": 0, 
                    "value_type_length": debug_value.value_type.byte_length
                }
                self.map[key] = register

class DbgRegister:
    def __init__(self, key, i, value_type_length):
        self.key = key
        self.i = i
        self.value_type_length = value_type_length

# Example usage:
manager = None  # Replace with your actual manager object
path = ["your", "path"]  # Replace with your actual path
command = DbgGetRegisterMapCommand(manager, path)
print(command.complete())  # This will print the register map
```

Please note that Python does not have direct equivalent of Java's `HashMap` and `List`. We use built-in dictionary (`{}`) for mapping and list (`[]`) for lists. Also, we do not need to specify types like in Java as it is dynamically typed language.