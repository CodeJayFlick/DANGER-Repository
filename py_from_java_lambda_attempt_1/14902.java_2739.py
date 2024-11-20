Here is the translation of the given Java code into equivalent Python:

```Python
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)

class Spell:
    def __init__(self, name):
        self.name = name


class Spellbook:
    def __init__(self, name):
        self.name = name
        self.spells = []

    def add_spell(self, spell):
        self.spells.append(spell)


class Wizard:
    def __init__(self, name):
        self.name = name
        self.spellbooks = []

    def add_spellbook(self, spellbook):
        self.spellbooks.append(spellbook)


def main():
    # Initialize data
    spells = [
        Spell("Ice dart"),
        Spell("Invisibility"),
        Spell("Stun bolt"),
        Spell("Confusion"),
        Spell("Darkness"),
        Spell("Fireball"),
        Spell("Enchant weapon"),
        Spell("Rock armour"),
        Spell("Light"),
        Spell("Bee swarm"),
        Spell("Haste"),
        Spell("Levitation"),
        Spell("Magic lock"),
        Spell("Summon hell bat"),
        Spell("Water walking"),
        Spell("Magic storm"),
        Spell("Entangle")
    ]

    spellbook1 = Spellbook("Book of Orgymon")
    for i in range(3):
        spellbook1.add_spell(spells[i])

    spellbook2 = Spellbook("Book of Aras")
    for i in range(3, 6):
        spellbook2.add_spell(spells[i])

    spellbook3 = Spellbook("Book of Kritior")
    for i in range(6, 9):
        spellbook3.add_spell(spells[i])

    spellbook4 = Spellbook("Book of Tamaex")
    for i in range(9, 12):
        spellbook4.add_spell(spells[i])

    spellbook5 = Spellbook("Book of Idores")
    for i in range(12, 15):
        spellbook5.add_spell(spells[i])

    spellbook6 = Spellbook("Book of Opaen")
    for i in range(15, 18):
        spellbook6.add_spell(spells[i])

    spellbook7 = Spellbook("Book of Kihione")
    for i in range(18, 20):
        spellbook7.add_spell(spells[i])

    wizards = [
        Wizard("Aderlard Boud"),
        Wizard("Anaxis Bajraktari"),
        Wizard("Xuban Munoa"),
        Wizard("Blasius Dehooge")
    ]

    for wizard in wizards:
        if i < 2:
            wizard.add_spellbook(spellbook1)
            wizard.add_spellbook(spellbook2)
        elif i == 3:
            wizard.add_spellbook(spellbook5)
            wizard.add_spellbook(spellbook6)
        else:
            wizard.add_spellbook(spellbook7)

    # Query the data
    for spell in spells:
        print(f"Spell: {spell.name}")

    wizards_with_idores = [wizard for wizard in wizards if "Book of Idores" in [spellbook.name for spellbook in wizard.spellbooks]]
    for wizard in wizards_with_idores:
        print(f"{wizard.name} has 'Book of Idores'")

    wizards_with_fireball = [wizard for wizard in wizards if any(spell.name == "Fireball" for spell in wizard.spellbooks)]
    for wizard in wizards_with_fireball:
        print(f"{wizard.name} has  Fireball")


if __name__ == "__main__":
    main()
```

This Python code is equivalent to the given Java code. It creates a list of `Spell` objects, then uses these spells to create lists of `Spellbook` and `Wizard` objects. The data initialization part is similar to the original Java code.

The query data section in this Python code does not exactly match the original Java code because it doesn't have direct equivalent for some operations like finding wizards with a specific spell or book, but I've tried my best to replicate those functionalities using list comprehensions and conditional statements.