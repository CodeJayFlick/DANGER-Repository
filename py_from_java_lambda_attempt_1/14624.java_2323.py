Here is the translation of the Java code to Python:

```Python
class RoyaltyObjectMother:
    def __init__(self):
        pass

    @staticmethod
    def create_sober_unhappy_king():
        return King()

    @staticmethod
    def create_drunk_king():
        king = King()
        king.make_drunk()
        return king

    @staticmethod
    def create_happy_king():
        king = King()
        king.make_happy()
        return king

    @staticmethod
    def create_happy_drunk_king():
        king = King()
        king.make_happy()
        king.make_drunk()
        return king

    @staticmethod
    def create_flirty_queen():
        queen = Queen()
        queen.set_flirtiness(True)
        return queen

    @staticmethod
    def create_not_flirty_queen():
        return Queen()


class King:
    def __init__(self):
        pass

    def make_drunk(self):
        pass

    def make_happy(self):
        pass


class Queen:
    def __init__(self):
        pass

    def set_flirtiness(self, flirtiness):
        self.flirtiness = flirtiness
```

Please note that I've assumed the existence of `King` and `Queen` classes in your Python code. These classes should have methods like `make_drunk`, `make_happy`, etc., similar to their Java counterparts.