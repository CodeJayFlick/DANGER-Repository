class IsSilent:
    def __init__(self):
        self.name = "Is Silent"
        self.description = "Checks whether an entity is silent i.e. its sounds are disabled."
        self.examples = ["target entity is silent"]
        self.since = "2.5"

    @property
    def name(self):
        return self._name

    @property
    def description(self):
        return self._description

    @property
    def examples(self):
        return self._examples

    @property
    def since(self):
        return self._since

    def check(self, entity: dict) -> bool:
        if 'silent' in entity and isinstance(entity['silent'], (bool)):
            return entity['silent']
        else:
            raise ValueError("Entity must have a 'silent' property")

# Registering the class
def register(cls):
    pass  # This is not implemented

register(IsSilent)
