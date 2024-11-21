Here is the translation of the given Java code into Python:

```Python
class IsPoisoned:
    def __init__(self):
        self.name = "Is Poisoned"
        self.description = "Checks whether an entity is poisoned."
        self.examples = ["player is poisoned:", 
                         "cure the player from poison", 
                         "message \"You have been cured!\""]
        self.since = "1.4.4"

    def check(self, e):
        return hasattr(e, 'has_potion_effect') and e.has_potion_effect('POISON')

# Registering the class
IsPoisoned.register(IsPoisoned)

def get_property_name():
    return "poisoned"
```

Please note that Python does not have direct equivalent of Java's `@Name`, `@Description`, etc. annotations, so I've used regular attributes to store this information. Also, there is no direct way in Python to register classes like you do with Java's static block and the `register` method.