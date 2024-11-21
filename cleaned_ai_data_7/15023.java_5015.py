class Character:
    def __init__(self, name):
        self.name = name
        self.fighter_class = None
        self.wizard_class = None
        self.weapon = None
        self.spell = None
        self.abilities = []

    @property
    def fighter_class(self):
        return self._fighter_class

    @fighter_class.setter
    def fighter_class(self, value):
        self._fighter_class = value

    @property
    def wizard_class(self):
        return self._wizard_class

    @wizard_class.setter
    def wizard_class(self, value):
        self._wizard_class = value

    @property
    def weapon(self):
        return self._weapon

    @weapon.setter
    def weapon(self, value):
        self._weapon = value

    @property
    def spell(self):
        return self._spell

    @spell.setter
    def spell(self, value):
        self._spell = value

    @property
    def abilities(self):
        return self._abilities

    @abilities.setter
    def abilities(self, value):
        self._abilities = value

    def __str__(self):
        if self.fighter_class:
            fighter_class_str = f" {self.fighter_class}"
        elif self.wizard_class:
            fighter_class_str = f" {self.wizard_class}"
        else:
            fighter_class_str = " with nothing"

        abilities_str = ""
        if self.abilities:
            abilities_str = f", wielding {' '.join(self.abilities)} abilities"

        return f"This is a{fighter_class_str} named {self.name} armed with a{self.weapon or self.spell}{abilities_str}."
