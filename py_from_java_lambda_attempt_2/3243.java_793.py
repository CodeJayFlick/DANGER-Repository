Here is the translation of the Java code to Python:
```
class ReorderModuleCmd:
    def __init__(self, tree_name: str, parent_module_name: str, child_name: str, index: int):
        self.tree_name = tree_name
        self.module_name = parent_module_name
        self.child_name = child_name
        self.index = index

    def apply_to(self, obj) -> bool:
        program = obj  # assume Program is a Python object that wraps the Java Program class
        listing = program.get_listing()
        module = listing.get_module(tree_name, module_name)
        try:
            module.move_child(child_name, index)
            return True
        except Exception as e:  # equivalent to NotFoundException in Java
            self.status_msg = str(e)  # set the status message
            return False

    def get_status_msg(self) -> str:
        return self.status_msg

    def get_name(self) -> str:
        return "Reorder"
```
Note that I've made some assumptions about how to translate certain parts of the code, such as:

* The `DomainObject` class is not directly equivalent in Python, so I just used a generic object type (`obj`) and assumed it would be wrapped by a Python object.
* The `NotFoundException` exception is not directly equivalent in Python, so I caught all exceptions with a single `except Exception as e:` block. You may want to refine this depending on the specific requirements of your application.

Also note that this code uses type hints (`: str`, etc.) which are optional but can help with static analysis and documentation.