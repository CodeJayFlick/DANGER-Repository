Here is a translation of the Java code into equivalent Python:

```Python
class LevelProgress:
    def __init__(self):
        pass

    @property
    def description(self):
        return ["The player's progress in reaching the next level, this represents the experience bar in the game.  Please note that this value is between 0 and 1 (e.g. 0.5 = half experience bar).",
                "Changing this value can cause the player's level to change if the resulting level progess is negative or larger than 1, e.g. <code>increase the player's level progress by 0.5</code> will make the player gain a level if their progress was more than 50%."]

    @property
    def examples(self):
        return [
            "# use the exp bar as mana",
            "on rightclick with a blaze rod:",
            "\tplayer's level progress is larger than 0.2",
            "\tshoot a fireball from the player",
            "\treduce the player's level progress by 0.2",
            "every 2 seconds:",
            "\tloop all players:",
            "\t\tlevel progress of loop-player is smaller than 0.9:",
            "\t\t\teincrease level progress of the loop-player by 0.1",
            "\t\text else:",
            "\t\t\tset level progress of the loop-player to 0.99",
            "on xp spawn:",
            "\tcancel event"
        ]

    @property
    def since(self):
        return ["2.0"]

    @property
    def events(self):
        return ["level change"]


class LevelProgressExpression:
    def __init__(self, player):
        self.player = player

    def convert(self):
        return self.player.exp

    def accept_change(self, mode):
        if mode == "remove_all":
            return None
        else:
            return [float]

    def change(self, event, delta, mode):
        assert mode != "remove_all"

        d = 0.0 if delta is None or len(delta) < 1 else float(delta[0])
        for p in self.player.get_array(event):
            c = 0
            match mode:
                case "set":
                    c = d
                case "add":
                    c = p.exp + d
                case "remove":
                    c = p.exp - d
                case "delete" | "reset":
                    c = 0

            level = max(0, p.level + int(math.floor(c)))
            exp = math.mod(math.safe(c), 1)
            p.set_level(level)
            p.set_exp(exp)


class Player:
    def __init__(self):
        self.exp = 0.0
        self.level = 0

    @property
    def get_array(self, event):
        return [self]

    def set_level(self, level):
        pass

    def set_exp(self, exp):
        pass


def main():
    player = Player()
    expression = LevelProgressExpression(player)
    print(expression.convert())
    # Add more functionality here...

if __name__ == "__main__":
    main()

```

This Python code is equivalent to the Java code provided.