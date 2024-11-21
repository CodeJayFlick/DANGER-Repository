# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class GiantController:
    def __init__(self, giant_model: 'GiantModel', view: 'GiantView'):
        self.giant = giant_model
        self.view = view

    @property
    def health(self):
        return self.giant.health

    @health.setter
    def health(self, value):
        self.giant.health = value

    @property
    def fatigue(self):
        return self.giant.fatigue

    @fatigue.setter
    def fatigue(self, value):
        self.giant.fatigue = value

    @property
    def nourishment(self):
        return self.giant.nourishment

    @nourishment.setter
    def nourishment(self, value):
        self.giant.nourishment = value

    def update_view(self):
        self.view.display_giant(self.giant)
