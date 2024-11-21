Here is the translation of the Java code to Python:

```Python
class ElfBlacksmith:
    ELFARSENAL = {}

    def __init__(self):
        for weapon_type in WeaponType:
            self.ELFARSENAL[weapon_type] = ElfWeapon(weapon_type)

    def manufacture_weapon(self, weapon_type: WeaponType) -> Weapon:
        return self.ELFARSENAL.get(weapon_type)

    def __str__(self) -> str:
        return "The elf blacksmith"


class ElfWeapon:
    def __init__(self, weapon_type):
        pass


class WeaponType(Enum):
    # Add your enum values here
    pass

# Usage example:

elf_blacksmith = ElfBlacksmith()
weapon = elf_blacksmith.manufacture_weapon(WeaponType.SOME_WEAPON_TYPE)
print(elf_blacksmith)  # Output: The elf blacksmith
```

Please note that Python does not have a direct equivalent to Java's `enum` type. Instead, you can use the built-in `Enum` class from the `enum` module or create your own enum-like system using classes and instances.

Also, in this translation, I assumed that `WeaponType` is an enumeration (like it was in the original Java code) and created a Python equivalent for it.