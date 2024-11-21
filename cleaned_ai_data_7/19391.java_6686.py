class Tree:
    def __init__(self):
        self.type = None
        self.blocks = []

    @staticmethod
    def register_effect():
        pass  # Skript.registerEffect(EffTree, "(grow|create|generate) tree [of type %structuretype%] [%directions%] [%locations%]", "(grow|create|generate) %structuretype% [%directions%] [%locations%]")

    @property
    def blocks(self):
        return self._blocks

    @blocks.setter
    def blocks(self, value):
        if isinstance(value, list):
            self._blocks = [Location(*block) for block in value]
        else:
            raise ValueError("Invalid input type. Please provide a list of Location objects.")

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        if isinstance(value, StructureType):
            self._type = value
        else:
            raise ValueError("Invalid input type. Please provide an instance of the StructureType class.")

    def init(self, exprs, matched_pattern, is_delayed, parser):
        self.type = exprs[0]
        self.blocks = Direction.combine(exprs[1], exprs[2])
        return True

    def execute(self, e):
        if not isinstance(e, Event):
            raise ValueError("Invalid event type. Please provide an instance of the Event class.")
        
        for block in self.blocks:
            assert block is not None
            self.type.grow(block.get_block())

    def __str__(self, e=None, debug=False):
        return f"grow tree of type {self.type} at locations: {[block.__str__() for block in self.blocks]}"
