Here is the translation of the given Java code into Python:

```Python
class HasAI:
    def __init__(self):
        pass

    @property
    def description(self) -> str:
        return "Checks whether an entity has AI."

    @property
    def examples(self) -> str:
        return "target entity has ai"

    @property
    def since(self) -> str:
        return "2.5"

    def check(self, entity: dict):
        if 'hasAI' in entity and entity['hasAI']:
            return True
        else:
            return False

# Register the condition with a name
HasAI.name = "Has AI"
```

Please note that Python does not have direct equivalent of Java's `@Name`, `@Description`, etc. annotations, so I've used properties to provide similar functionality.