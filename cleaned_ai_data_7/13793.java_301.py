import logging

class Hammer:
    def __init__(self, enchantment):
        self.enchantment = enchantment

    @property
    def enchantment(self):
        return self._enchantment

    @enchantment.setter
    def enchantment(self, value):
        if not isinstance(value, Enchantment):
            raise ValueError("Enchantment must be an instance of Enchantment")
        self._enchantment = value

    def wield(self):
        logging.info("The hammer is wielded.")
        self.enchantment.on_activate()

    def swing(self):
        logging.info("The hammer is swung.")
        self.enchantment.apply()

    def unwield(self):
        logging.info("The hammer is unwielded.")
        self.enchantment.on_deactivate()

class Enchantment:
    pass

# Example usage
enchantment = Enchantment()
hammer = Hammer(enchantment)
