Here is a translation of the Java code into equivalent Python:

```Python
# This file is part of Skript.
#
# Skript is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

import bukkit

class BedExpression:
    def __init__(self):
        pass

    @property
    def name(self):
        return "Bed"

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def description(self):
        return "The bed location of a player, i.e. the spawn point of a player if he ever slept in a bed and the bed still exists and is unobstructed."

    @description.setter
    def description(self, value):
        self._description = value

    @property
    def examples(self):
        return ["bed of player exists:", "teleport player to the player's bed", "else: teleport the player to the world's spawn point"]

    @examples.setter
    def examples(self, value):
        self._examples = value

    @property
    def since(self):
        return "2.0"

    @since.setter
    def since(self, value):
        self._since = value

class Player:
    def __init__(self):
        pass

    def get_bed_spawn_location(self):
        # This method should be implemented in the actual Bukkit API.
        pass

    def set_bed_spawn_location(self, location, force=False):
        # This method should be implemented in the actual Bukkit API.
        pass


class BedExpressionConverter:
    @staticmethod
    def convert(player: Player) -> bukkit.Location:
        return player.get_bed_spawn_location()

    @staticmethod
    def accept_change(mode: str) -> list or None:
        if mode == "set" or mode == "delete":
            return [bukkit.Location]
        else:
            return None

    @staticmethod
    def change(event, delta=None, mode=""):
        for player in event.get_players():
            if delta is not None and len(delta) > 0:
                location = bukkit.Location.from_string(delta[0])
                player.set_bed_spawn_location(location)
            else:
                player.set_bed_spawn_location(None)


def register(expression_class):
    # This method should be implemented to register the expression class.
    pass

register(BedExpression)

if __name__ == "__main__":
    bed_expression = BedExpression()
    print(bed_expression.name)  # prints: "Bed"
    print(bed_expression.description)
    for example in bed_expression.examples:
        print(example)
    print(bed_expression.since)  # prints: "2.0"

```

This Python code is equivalent to the Java code provided, but it does not include any actual implementation of Bukkit API methods as they are specific to a particular Minecraft server and may vary depending on the version or plugin used.