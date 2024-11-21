class NestedDelaySlotException(Exception):
    def __init__(self):
        super().__init__("Nested delay slotted instruction not permitted")
