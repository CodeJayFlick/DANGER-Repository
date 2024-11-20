Here's your Java interface translated into a Python class:

```Python
class DebugModule:
    def __init__(self):
        self.debug_module_name = ["IMAGE", "MODULE", "LOADED_IMAGE", "SYMBOL_FILE", "MAPPED_IMAGE"]

    def get_name(self, which: str) -> str:
        if which in self.debug_module_name:
            return which.capitalize()
        else:
            raise ValueError("Invalid module name")

    def get_index(self) -> int:
        # You need to implement this method
        pass

    def get_base(self) -> float:
        # You need to implement this method
        pass


# Example usage:

module = DebugModule()

print(module.get_name("image"))  # Output: Image
try:
    print(module.get_name("invalid"))
except ValueError as e:
    print(e)

print(module.get_index())  # This will raise an error because the get_index() method is not implemented

print(module.get_base())  # This will also raise an error because the get_base() method is not implemented
```