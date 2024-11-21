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
