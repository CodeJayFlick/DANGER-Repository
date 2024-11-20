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

