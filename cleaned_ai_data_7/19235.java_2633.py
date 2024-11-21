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
