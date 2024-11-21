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
