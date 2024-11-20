class EyeLocation:
    def __init__(self):
        pass

    @property
    def name(self):
        return "Head location"

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def description(self):
        return ["The location of an entity'\\s head, mostly useful for players and e.g. looping blocks in the player'\\s line of sight.",
                "Please note that this location is only accurate for entities whose head is exactly above their center, i.e. players, endermen, zombies, skeletons, etc., but not sheep, pigs or cows."]

    @property
    def examples(self):
        return ["set the block at the player'\\s head to air",
                "set the block in front of the player'\\s eyes to glass",
                "loop blocks in front of the player'\\s head:"]

    @property
    def since(self):
        return "2.0"

class LivingEntity:
    def __init__(self, eye_location=None):
        self.eye_location = eye_location

def get_eye_location(entity: 'LivingEntity') -> Location:
    if isinstance(entity, LivingEntity):
        return entity.eye_location
    else:
        raise TypeError("Invalid type")

# Usage example:

entity1 = LivingEntity(Location(0.5, 0.5, 0))
print(get_eye_location(entity1))

