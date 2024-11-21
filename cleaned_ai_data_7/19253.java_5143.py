class IsInvulnerable:
    def __init__(self):
        self.name = "Is Invulnerable"
        self.description = "Checks whether an entity is invulnerable."
        self.examples = ["target entity is invulnerable"]
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

    def check(self, entity):
        if hasattr(entity, 'is_invulnerable'):
            return entity.is_invulnerable()
        else:
            raise AttributeError("Entity does not have an is_invulnerable method")

# Register the class with a name and description for documentation purposes
def register(cls):
    pass  # This function would typically be used to register classes in some kind of registry or database

register(IsInvulnerable)
