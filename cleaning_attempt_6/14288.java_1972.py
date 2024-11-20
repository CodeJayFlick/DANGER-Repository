import logging

class HealingPotion:
    def drink(self):
        logging.info("You feel healed. (Potion={})".format(id(self)))

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
