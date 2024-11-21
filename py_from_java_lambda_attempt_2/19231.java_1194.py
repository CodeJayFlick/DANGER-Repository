Here is the translation of the given Java code into Python:

```Python
class HasClientWeather:
    def __init__(self):
        self.description = "Checks whether the given players have a custom client weather"
        self.name = "Has Client Weather"

    @property
    def description(self):
        return self.__description

    @description.setter
    def description(self, value):
        self.__description = value

    @property
    def name(self):
        return self.__name

    @name.setter
    def name(self, value):
        self.__name = value

    def __str__(self):
        return f"Has Client Weather: {self.name} - {self.description}"

class Player:
    def __init__(self, player_weather=None):
        self.player_weather = player_weather

    @property
    def get_player_weather(self):
        return self.player_weather


def check(player):
    if isinstance(player, Player) and player.get_player_weather is not None:
        return True
    else:
        return False


class CondHasClientWeather:
    def __init__(self):
        pass

    def register(cls):
        cls.register = lambda: print("Registered Has Client Weather condition")

    @classmethod
    def register(cls, *args, **kwargs):
        if 'register' in kwargs:
            del(kwargs['register'])
        return super(CondHasClientWeather, cls).__init__(*args, **kwargs)

    @staticmethod
    def main():
        player = Player()
        print(check(player))

if __name__ == "__main__":
    CondHasClientWeather.main()

```

Please note that this is a direct translation of the given Java code into Python. However, it may not be exactly what you are looking for as there might be some differences in how certain concepts are handled between the two languages.