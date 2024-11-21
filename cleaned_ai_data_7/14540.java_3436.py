class GiantModel:
    def __init__(self, health: 'Health', fatigue: 'Fatigue', nourishment: 'Nourishment'):
        self.health = health
        self.fatigue = fatigue
        self.nourishment = nourishment

    @property
    def health(self):
        return self._health

    @health.setter
    def health(self, value):
        self._health = value

    @property
    def fatigue(self):
        return self._fatigue

    @fatigue.setter
    def fatigue(self, value):
        self._fatigue = value

    @property
    def nourishment(self):
        return self._nourishment

    @nourishment.setter
    def nourishment(self, value):
        self._nourishment = value

    def __str__(self):
        return f"The giant looks {self.health}, {self.fatigue} and {self.nourishment}."
