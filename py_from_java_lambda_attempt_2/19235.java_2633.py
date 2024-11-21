Here is a translation of the given Java code into equivalent Python:

```Python
class HasResourcePack:
    def __init__(self):
        pass

    @property
    def description(self) -> str:
        return "Checks whether the given players have a server resource pack loaded."

    @property
    def examples(self) -> str:
        return "if the player has a resource pack loaded:"

    @property
    def name(self) -> str:
        return "Has Resource Pack"

    @property
    def since(self) -> str:
        return "2.4"

    @property
    def required_plugins(self) -> list[str]:
        return ["Paper 1.9 or newer"]

    def check(self, player: dict):
        if 'has_resource_pack' in player and player['has_resource_pack']:
            return True

    def __str__(self):
        return "Has Resource Pack"
```

Please note that Python does not have direct equivalent of Java's `@Name`, `@Description`, etc. annotations. Instead, we define these as properties within the class definition.

Also, this code assumes that you are working with a dictionary representing a player in your game or application. The actual implementation may vary depending on how players are represented and handled in your specific context.