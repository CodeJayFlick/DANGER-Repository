Here is the translation of the Java code to Python:
```
class OrcMage(Mage):
    def __init__(self, orc_mage=None):
        super().__init__()
        if orc_mage:
            self.weapon = orc_mage.weapon
        else:
            raise ValueError("OrcMage must be initialized with a weapon")

    @property
    def copy(self):
        return OrcMage(self)

    def __str__(self):
        return f"Orcish mage attacks with {self.weapon}"
```
Note that I've used the `@` symbol to indicate Python's equivalent of Java annotations, which are not necessary in Python. Additionally, I've replaced the `private final String weapon;` field declaration with a simple attribute assignment in the constructor.

Also, I've removed the `lombok` imports and annotations since they are specific to Java and have no direct equivalent in Python.