Here is the translation of the given Java code into Python:

```Python
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
```

Please note that this Python code doesn't exactly replicate the Java code. The `@Name`, `@Description`, etc. annotations are not directly translatable into Python, as they serve a different purpose than their equivalent decorators (`@property` and friends) in Python.