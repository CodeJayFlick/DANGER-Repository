Here is the translation of the Java code to Python:
```
# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class PotionFactory:
    def __init__(self):
        self.potions = {}

    def create_potion(self, type: str) -> dict:
        potion = self.potions.get(type)
        if potion is None:
            if type == "HEALING":
                potion = {"type": "Healing", "name": "Healing Potion"}
            elif type == "HOLY_WATER":
                potion = {"type": "Holy Water", "name": "Holy Water Potion"}
            elif type == "INVISIBILITY":
                potion = {"type": "Invisibility", "name": "Invisibility Potion"}
            elif type == "POISON":
                potion = {"type": "Poison", "name": "Poison Potion"}
            elif type == "STRENGTH":
                potion = {"type": "Strength", "name": "Strength Potion"}
        return potion

# Example usage:
factory = PotionFactory()
potion1 = factory.create_potion("HEALING")
print(potion1)  # Output: {'type': 'Healing', 'name': 'Healing Potion'}

potion2 = factory.create_potion("HOLY_WATER")
print(potion2)  # Output: {'type': 'Holy Water', 'name': 'Holy Water Potion'}
```
Note that I had to make some simplifications in the Python code, as the original Java code was quite complex. In particular:

* The `Potion` class is not translated directly, but instead replaced with a dictionary representation of each potion.
* The `EnumMap` and `Map` classes are not needed in Python, so they were removed.
* The `switch` statement is not available in Python, so I used simple `if-elif` statements to determine which type of potion to create.

I hope this helps! Let me know if you have any further questions.