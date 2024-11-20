class Wizard:
    def __init__(self):
        self.id = None
        self.name = ''
        self.spellbooks = set()

    def __str__(self):
        return self.name


# Note: In Python, we don't have direct equivalent to Java's @Entity and @Table annotations.
# We can use a dictionary or a class with attributes as an alternative.

class BaseEntity:
    pass

class Spellbook:
    def __init__(self):
        self.wizards = set()

wizard1 = Wizard()
print(wizard1)

wizard2 = Wizard('New Name')
print(wizard2)
