import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)

class SimpleTroll:
    def __init__(self):
        self.attack_power = 10

    def attack(self):
        LOGGER.info("The simple troll attacks!")

    def fleeBattle(self):
        LOGGER.info("The simple troll flees the battle!")


class ClubbedTroll(SimpleTroll):
    def __init__(self, trolled_troll):
        super().__init__()
        self.attack_power = 20
        self.trolled_troll = trolled_troll

    def attack(self):
        LOGGER.info("The clubbed troll attacks!")
        self.trolled_troll.attack()

    def fleeBattle(self):
        LOGGER.info("The clubbed troll flees the battle!")


def main():
    # simple troll
    LOGGER.info("A simple looking troll approaches.")
    t = SimpleTroll()
    t.attack()
    t.fleeBattle()
    LOGGER.info("Simple troll power: {}.\n".format(t.attack_power))

    # change the behavior of the simple troll by adding a decorator
    LOGGER.info("A troll with huge club surprises you.")
    ct = ClubbedTroll(t)
    ct.attack()
    ct.fleeBattle()
    LOGGER.info("Clubbed troll power: {}.\n".format(ct.attack_power))


if __name__ == "__main__":
    main()

