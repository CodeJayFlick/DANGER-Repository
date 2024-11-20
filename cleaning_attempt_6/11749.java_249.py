class SpaceSymbol:
    def __init__(self, location, space):
        super().__init__(location, space.name)
        self.space = space

    @property
    def space(self):
        return self._space

    @space.setter
    def space(self, value):
        self._space = value

    def get_type(self):
        return "space_symbol"
