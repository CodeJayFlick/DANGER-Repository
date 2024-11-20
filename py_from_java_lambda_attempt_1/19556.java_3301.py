Here is the equivalent Python code:

```Python
class Exhaustion:
    def __init__(self):
        pass

    @property
    def description(self):
        return "The exhaustion of a player. This is mainly used to determine the rate of hunger depletion."

    @property
    def examples(self):
        return ["set exhaustion of all players to 1"]

    @property
    def since(self):
        return "2.2-dev35"

    def get_return_type(self):
        return float

    def get_property_name(self):
        return "exhaustion"

    def convert(self, player: dict) -> float:
        if 'exhaustion' in player:
            return player['exhaustion']
        else:
            return 0.0

    def accept_change(self, mode: str, delta: list) -> None:
        exhaustion = delta[0]
        if mode == "ADD":
            for player in get_expr().get_array():
                player['exhaustion'] += exhaustion
        elif mode == "REMOVE":
            for player in get_expr().get_array():
                player['exhaustion'] -= exhaustion
        elif mode == "SET":
            for player in get_expr().get_array():
                player['exhaustion'] = exhaustion
        elif mode in ["DELETE", "REMOVE_ALL", "RESET"]:
            for player in get_expr().get_array():
                player['exhaustion'] = 0.0

    def register(self):
        return {
            'class': self.__class__,
            'return_type': float,
            'property_name': "exhaustion",
            'players': True
        }
```

Please note that Python does not support static methods or variables like Java, so the `register` method is replaced with a regular instance method. Also, there's no direct equivalent of Java's annotations in Python, but you can achieve similar functionality using properties and docstrings.