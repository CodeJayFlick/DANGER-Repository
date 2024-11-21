Here is the translation of the given Java code into Python:

```Python
import logging

class Character:
    def __init__(self):
        self.stats = {}

    @property
    def stats(self):
        return self._stats

    @stats.setter
    def stats(self, value):
        self._stats = value


def main():
    # set up
    char_proto = Character()
    char_proto.stats[Stats.STRENGTH] = 10
    char_proto.stats[Stats.AGILITY] = 10
    char_proto.stats[Stats.ARMOR] = 10
    char_proto.stats[Stats.ATTACK_POWER] = 10

    mage_proto = Character(type='MAGE', parent=char_proto)
    mage_proto.stats[Stats.INTELLECT] = 15
    mage_proto.stats[Stats.SPIRIT] = 10

    war_proto = Character(type='WARRIOR', parent=char_proto)
    war_proto.stats[Stats.RAGE] = 15
    war_proto.stats[Stats.ARMOR] = 15  # boost default armor for warrior

    rogue_proto = Character(type='ROGUE', parent=char_proto)
    rogue_proto.stats[Stats.ENERGY] = 15
    rogue_proto.stats[Stats.AGILITY] = 15  # boost default agility for rogue

    # usage
    mag = Character('Player_1', mage_proto)
    mag.stats[Stats.ARMOR] = 8
    logging.info(str(mag))

    warrior = Character('Player_2', war_proto)
    logging.info(str(warrior))

    rogue = Character('Player_3', rogue_proto)
    logging.info(str(rogue))

    rogue_double = Character('Player_4', rogue)
    rogue_double.stats[Stats.ATTACK_POWER] = 12
    logging.info(str(rogue_double))


if __name__ == "__main__":
    main()
```

Please note that Python does not have direct equivalent of Java's `@Slf4j` annotation, which is used for logging. In the above code, I've simply imported the built-in `logging` module and used its functions to log messages.

Also, in Python, we don't need to explicitly define a constructor (`__init__`) as it will be automatically called when an object of that class is created.