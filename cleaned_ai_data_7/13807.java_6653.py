class Weapon:
    DAGGER = "Dagger"
    SWORD = "Sword"
    AXE = "Axe"
    WARHAMMER = "Warhammer"
    BOW = "Bow"

    def __str__(self):
        return self.name().lower()
