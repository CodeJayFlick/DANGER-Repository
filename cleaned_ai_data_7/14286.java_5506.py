class AlchemistShop:
    def __init__(self):
        self.top_shelf = [PotionFactory().create_potion(PotionType.INVISIBILITY),
                          PotionFactory().create_potion(PotionType.INVISIBILITY),
                          PotionFactory().create_potion(PotionType.STRENGTH),
                          PotionFactory().create_potion(PotionType.HEALING),
                          PotionFactory().create_potion(PotionType.INVISIBILITY),
                          PotionFactory().create_potion(PotionType.STRENGTH),
                          PotionFactory().create_potion(PotionType.HEALING),
                          PotionFactory().create_potion(PotionType.HEALING)]

        self.bottom_shelf = [PotionFactory().create_potion(PotionType.POISON),
                             PotionFactory().create_potion(PotionType.POISON),
                             PotionFactory().create_potion(PotionType.POISON),
                             PotionFactory().create_potion(PotionType.HOLY_WATER),
                             PotionFactory().create_potion(PotionType.HOLY_WATER)]

    def get_top_shelf(self):
        return self.top_shelf[:]

    def get_bottom_shelf(self):
        return self.bottom_shelf[:]

    def drink_potions(self):
        import logging
        logger = logging.getLogger(__name__)
        logger.info("Drinking top shelf potions")
        for potion in self.top_shelf:
            potion.drink()
        logger.info("Drinking bottom shelf potions")
        for potion in self.bottom_shelf:
            potion.drink()


class PotionFactory:
    def create_potion(self, type):
        # implement your logic here
        pass


class PotionType:
    INVISIBILITY = "INVISIBILITY"
    STRENGTH = "STRENGTH"
    HEALING = "HEALING"
    POISON = "POISON"
    HOLY_WATER = "HOLY_WATER"


# Usage example:

alchemist_shop = AlchemistShop()
print(alchemist_shop.get_top_shelf())
print(alchemist_shop.get_bottom_shelf())

alchemist_shop.drink_potions()

