class FillClauseComponent:
    def __init__(self):
        self.fill_types = {}

    @property
    def fill_types(self):
        return self._fill_types

    @fill_types.setter
    def fill_types(self, value):
        self._fill_types = value


# Note: Python does not have direct equivalent of Java's package declaration.
