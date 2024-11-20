class IsLeashed:
    def __init__(self):
        self.name = "Is Leashed"
        self.description = "Checks to see if an entity is currently leashed."
        self.examples = ["target entity is leashed"]
        self.since = "2.5"

    def check(self, entity: 'LivingEntity') -> bool:
        return entity.is_leashed()

class LivingEntity:
    def __init__(self):
        pass

    def is_leashed(self) -> bool:
        # This method should be implemented based on the actual implementation
        pass


# Registering the condition with a name and property type
def register_condition(name: str, prop_type: str, prop_name: str, entities: str):
    print(f"Registering {name} as {prop_type} for {entities} with property name {prop_name}")


register_condition("Is Leashed", "BE", "leashed", "livingentities")
