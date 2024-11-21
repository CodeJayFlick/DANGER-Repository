Here is the translation of the Java code to Python:
```
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
```
Note that I had to make some assumptions about the `Enchantment` class, as it was not provided in the original Java code. In Python, we don't have a direct equivalent of Java's annotations (such as `@Slf4j` and `@AllArgsConstructor`), so I simply omitted them.

Also, I used Python's built-in logging module instead of SLF4J. If you want to use SLF4J in Python, you would need to use a library like PySLF4J or logback-python.