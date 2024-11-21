class SlotIndex:
    def __init__(self):
        self.description = "Index of an inventory slot."
        self.name = "Slot Index"
        self.since = "2.2-dev35"

    @property
    def examples(self):
        return ["if index of event-slot is 10:", "\tsend \"You bought a pie!\""]

class Slot:
    pass

class SlotWithIndex(Slot):
    def __init__(self, index):
        self.index = index

def convert(slot: Slot) -> int | None:
    if isinstance(slot, SlotWithIndex):
        return slot.index
    else:
        return 0

slot_index = SlotIndex()
