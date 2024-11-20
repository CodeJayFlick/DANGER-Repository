Here is the translation of the given Java code into Python:

```Python
class IsSneaking:
    def __init__(self):
        self.name = "Is Sneaking"
        self.description = "Checks whether a player is sneaking."
        self.examples = ["# prevent mobs from seeing sneaking players if they are at least 4 meters apart",
                         "# on target:",
                         "     target is sneaking",
                         "     distance of target and the entity is bigger than 4",
                         "     cancel the event"]
        self.since = "1.4.4"

    def check(self, p):
        return p.is_sneaking()

if __name__ == "__main__":
    register(IsSneaking(), "sneaking", "players")
```

Please note that this is a direct translation of your Java code into Python and does not include any error handling or exception checking.