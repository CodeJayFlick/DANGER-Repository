class Hero:
    def __init__(self, profession: str, name: str):
        self.profession = profession
        self.name = name


class Builder:
    def __init__(self, profession: str, name: str):
        self.hero = Hero(profession, name)

    @property
    def hair_color(self) -> str:
        return self._hair_color

    @hair_color.setter
    def hair_color(self, value: str):
        self._hair_color = value

    @property
    def weapon(self) -> str:
        return self._weapon

    @weapon.setter
    def weapon(self, value: str):
        self._weapon = value


def main():
    mage = Builder("MAGE", "Riobard").with_hair_color("BLACK").with_weapon("DAGGER").build()
    print(mage)

    warrior = Builder("WARRIOR", "Amberjill") \
               .with_hair_color("BLOND") \
               .with_hair_type("LONG_ CURLY") \
               .with_armor("CHAIN_MAIL") \
               .with_weapon("SWORD") \
               .build()
    print(warrior)

    thief = Builder("THIEF", "Desmond").with_hair_type("BALD").with_weapon("BOW").build()
    print(thief)


if __name__ == "__main__":
    main()

