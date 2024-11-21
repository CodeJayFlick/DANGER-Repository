class FamilySymbol:
    def __init__(self, location):
        super().__init__(location)

    def __init__(self, location, nm):
        super().__init__(location, nm)

    def get_pattern_value(self):
        raise NotImplementedError("Abstract method must be implemented")
