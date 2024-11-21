class IsSprinting:
    def __init__(self):
        self.name = "Is Sprinting"
        self.description = "Checks whether a player is sprinting."
        self.examples = ["player is not sprinting"]
        self.since = "1.4.4"

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

class Player:
    def __init__(self, is_sprinting=False):
        self.is_sprinting = is_sprinting

    def is_sprinting(self):
        return self.is_sprinting


def check(player: Player) -> bool:
    return player.is_sprinting()


if __name__ == "__main__":
    register(IsSprinting)
