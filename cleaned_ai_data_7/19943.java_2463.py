class DroppedItemSlot:
    def __init__(self, item):
        self.entity = item

    @property
    def item(self):
        return self.entity.item_stack

    @item.setter
    def item(self, item):
        assert item is not None
        self.entity.set_item_stack(item)

    @property
    def amount(self):
        return self.entity.item_stack.amount

    @amount.setter
    def amount(self, amount):
        self.entity.set_amount(amount)

    def is_same_slot(self, other):
        if isinstance(other, DroppedItemSlot) and other.entity == self.entity:
            return True
        else:
            return False

    def __str__(self, e=None, debug=False):
        from ch.njol.skript import Classes
        return str(Classes.toString(self.item))
