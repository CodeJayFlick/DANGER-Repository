class WeatherType:
    def __init__(self):
        self.names = []
        self.adjective = None

    CLEAR = WeatherType()
    RAIN = WeatherType()
    THUNDER = WeatherType()

    by_name = {}

    @classmethod
    def add_listener(cls, listener):
        cls.by_name.clear()
        for t in [cls.CLEAR, cls.RAIN, cls.THUNDER]:
            t.names = Language.get_list(f"weather.{t.__class__.__name__}.name")
            t.adjective = Language.get(f"weather.{t.__class__.__name__}.adjective")
            for name in t.names:
                cls.by_name[name] = t

    @classmethod
    def parse(cls, s):
        return cls.by_name.get(s)

    @classmethod
    def from_world(cls, world):
        if world.thundering and world.has_storm():
            return WeatherType.THUNDER
        elif world.has_storm():
            return WeatherType.RAIN
        else:
            return WeatherType.CLEAR

    @classmethod
    def from_event(cls, e):
        if isinstance(e, WeatherChangeEvent):
            return cls.from_weather_change_event(e)
        elif isinstance(e, ThunderChangeEvent):
            return cls.from_thunder_change_event(e)
        assert False
        return WeatherType.CLEAR

    @classmethod
    def from_weather_change_event(cls, e):
        if not e.to_weather_state():
            return WeatherType.CLEAR
        if e.world.is_thundering():
            return WeatherType.THUNDER
        else:
            return WeatherType.RAIN

    @classmethod
    def from_thunder_change_event(cls, e):
        if e.to_thunder_state():
            return WeatherType.THUNDER
        elif e.world.has_storm():
            return WeatherType.RAIN
        else:
            return WeatherType.CLEAR

    @classmethod
    def from_player(cls, player):
        weather = player.player_weather
        if weather is None:
            return None
        match weather:
            case org.bukkit.WeatherType.DOWNFALL:
                return WeatherType.RAIN
            case _:
                return None

    def set_weather(self, player):
        match self:
            case WeatherType.RAIN | WeatherType.THUNDER:
                player.set_player_weather(org.bukkit.WeatherType.DOWNFALL)
            case WeatherType.CLEAR:
                player.set_player_weather(org.bukkit.WeatherType.CLEAR)

    def __str__(self):
        return self.names[0]

    @property
    def adjective(self):
        return self.adjective

    def is_weather(self, world):
        return self.is_weather(world.has_storm(), world.is_thundering())

    def is_weather(self, rain, thunder):
        match self:
            case WeatherType.CLEAR:
                return not thunder and not rain
            case WeatherType.RAIN:
                return not thunder and rain
            case WeatherType.THUNDER:
                return thunder and rain

    def set_weather(self, world):
        if world.is_thundering() != (self is WeatherType.THUNDER):
            world.set_thundering(self == WeatherType.THUNDER)
        if world.has_storm() == (self is WeatherType.CLEAR):
            world.set_storm(self != WeatherType.CLEAR)

WeatherType.add_listener()
