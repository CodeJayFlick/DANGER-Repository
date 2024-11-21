class ElfWeapon:
    def __init__(self, weapon_type: str):
        self.weapon_type = weapon_type

    @property
    def weapon_type(self) -> str:
        return self._weapon_type

    def __str__(self) -> str:
        return f"an elven {self.weapon_type}"
