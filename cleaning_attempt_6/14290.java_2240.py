import logging

class InvisibilityPotion:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def drink(self):
        self.logger.info("You become invisible. (Potion={})".format(id(self)))

# Usage example:
if __name__ == "__main__":
    potion = InvisibilityPotion()
    potion.drink()

