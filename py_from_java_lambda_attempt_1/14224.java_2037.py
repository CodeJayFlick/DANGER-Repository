Here is the translation of the given Java code into Python:

```Python
class FactoryMethodTest:
    def test_orc_blacksmith_with_spear(self):
        blacksmith = OrcBlacksmith()
        weapon = blacksmith.manufacture_weapon(WeaponType.SPEAR)
        self._verify_weapon(weapon, WeaponType.SPEAR, OrcWeapon)

    def test_orc_blacksmith_with_axe(self):
        blacksmith = OrcBlacksmith()
        weapon = blacksmith.manufacture_weapon(WeaponType.AXE)
        self._verify_weapon(weapon, WeaponType.AXE, OrcWeapon)

    def test_elf_blacksmith_with_short_sword(self):
        blacksmith = ElfBlacksmith()
        weapon = blacksmith.manufacture_weapon(WeaponType.SHORT_SWORD)
        self._verify_weapon(weapon, WeaponType.SHORT_SWORD, ElfWeapon)

    def test_elf_blacksmith_with_spear(self):
        blacksmith = ElfBlacksmith()
        weapon = blacksmith.manufacture_weapon(WeaponType.SPEAR)
        self._verify_weapon(weapon, WeaponType.SPEAR, ElfWeapon)

    def _verify_weapon(self, weapon, expected_weapon_type, clazz):
        if not isinstance(weapon, clazz):
            raise AssertionError(f"Weapon must be an object of: {clazz.__name__}")
        if weapon.get_weapon_type() != expected_weapon_type:
            raise AssertionError(
                f"Weapon must be of weaponType: {expected_weapon_type}"
            )


class OrcBlacksmith:
    def manufacture_weapon(self, weapon_type):
        # Implementation for orc blacksmith
        pass


class ElfBlacksmith:
    def manufacture_weapon(self, weapon_type):
        # Implementation for elf blacksmith
        pass


class Weapon:
    def __init__(self, weapon_type):
        self.weapon_type = weapon_type

    def get_weapon_type(self):
        return self.weapon_type


class OrcWeapon(Weapon):
    pass


class ElfWeapon(Weapon):
    pass


# Enum for different types of weapons
class WeaponType:
    SPEAR = 1
    AXE = 2
    SHORT_SWORD = 3

```

Please note that the above Python code is a direct translation from Java and does not include any actual implementation. The `OrcBlacksmith`, `ElfBlacksmith`, `Weapon`, `OrcWeapon` and `ElfWeapon` classes are just placeholders for their respective implementations in Java, which would typically involve creating objects of specific types based on the input parameters.