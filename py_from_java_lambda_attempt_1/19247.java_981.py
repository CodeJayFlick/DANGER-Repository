Here is the equivalent Python code:

```Python
class IsEmpty:
    def __init__(self):
        pass

    @staticmethod
    def register():
        return {"empty": ["inventories/slots/strings"]}

    def check(self, o):
        if isinstance(o, str):
            return not o.strip()
        elif isinstance(o, dict):  # assuming Inventory is a dictionary in Python
            for item in o.values():
                if item:
                    return False
            return True
        elif hasattr(o, 'item'):  # assuming Slot has an 'item' attribute
            return o.item is None or o.item.type == "AIR"
        else:
            assert False, f"Unsupported type: {type(o)}"
            return False

    def get_property_name(self):
        return "empty"

# Example usage:
cond = IsEmpty()
print(cond.check("Hello"))  # returns True
print(cond.check({"item1": None, "item2": None}))  # returns True
slot = {"item": None}
print(cond.check(slot))  # returns True

```

Please note that Python does not have direct equivalents for Java's `@Name`, `@Description`, etc. annotations. These are used to provide documentation and metadata about the class, method or variable in a program.