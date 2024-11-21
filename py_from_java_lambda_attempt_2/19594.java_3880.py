Here is the translation of the given Java code into Python:

```Python
class InventorySlot:
    def __init__(self):
        self.slots = None
        self.invis = None

    @staticmethod
    def register_expression():
        Skript.register_expression(InventorySlot, Slot, ExpressionType.COMBINED,
                                  "[the] slot[es] %numbers% of %inventory%", "%inventory%'s slot[es] %numbers%")

    def init(self, exprs, matched_pattern):
        if matched_pattern == 0:
            self.slots = exprs[0]
            self.invis = exprs[1]
        else:
            self.slots = exprs[1]
            self.invis = exprs[0]

    @property
    def is_single(self):
        return self.slots.is_single

    @property
    def get_return_type(self):
        return Slot

    def __str__(self, e=None, debug=False):
        if not isinstance(e, Event) and not isinstance(debug, bool):
            raise TypeError("Invalid type for event or debug")
        return f"slots {self.slots} of {self.invis}"

class Slot:
    pass
```

Please note that this is a direct translation from Java to Python. It may require some adjustments based on the actual usage and requirements in your specific project.

Also, please be aware that Python does not have built-in support for static methods or properties like Java has. The `register_expression` method was moved into an instance method (`__init__`) as it seems to be related to initialization of this class.