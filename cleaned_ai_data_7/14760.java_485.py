class OrcMage(Mage):
    def __init__(self, orc_mage=None):
        super().__init__()
        if orc_mage:
            self.weapon = orc_mage.weapon
        else:
            raise ValueError("OrcMage must be initialized with a weapon")

    @property
    def copy(self):
        return OrcMage(self)

    def __str__(self):
        return f"Orcish mage attacks with {self.weapon}"
