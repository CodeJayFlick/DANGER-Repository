Here is your Java class translated into a Python equivalent:

```Python
class RecoveredClass:
    def __init__(self, name: str, category_path: object, namespace: object, data_type_manager: object):
        self.name = name
        self.category_path = category_path
        self.namespace = namespace
        self.data_type_manager = data_type_manager

        self.vftable_addresses = []
        self.all_class_virtual_functions = []

    def get_name(self) -> str:
        return self.name

    def get_virtual_functions(self, vftable_address: object) -> list:
        return self.vftable_to_vfunctions_map.get(vftable_address)

    def get_all_virtual_functions(self) -> list:
        return self.all_class_virtual_functions

    # ... (all the other methods)
```

Note that Python does not have direct equivalents for Java's `public`, `private`, and `static` keywords. In this translation, I've omitted these modifiers as they are not necessary in Python.

Also note that Python is dynamically typed, so you don't need to specify types like you do in Java. However, if you want your code to be more readable or enforce certain constraints at runtime, you can use type hints (the `: str` and `-> list` syntax) as I've done here.