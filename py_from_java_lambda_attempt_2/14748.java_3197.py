Here is the translation of the given Java code into Python:

```
# The MIT License
# Copyright © 2014-2021 Ilkka Seppälä

class Stats:
    """All possible attributes that Character can have."""
    AGILITY = 'Agility'
    STRENGTH = 'Strength'
    ATTACK_POWER = 'Attack Power'
    ARMOR = 'Armor'
    INTELLECT = 'Intellect'
    SPIRIT = 'Spirit'
    ENERGY = 'Energy'
    RAGE = 'Rage'

Stats.__doc__ = """All possible attributes that Character can have."""
```

Note: Python does not support enum directly like Java. So, we are using class to achieve the same functionality.