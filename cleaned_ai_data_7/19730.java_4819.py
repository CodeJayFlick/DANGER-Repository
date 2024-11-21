import datetime as dt


class WeatherType:
    CLEAR = 0
    RAINY = 1
    THUNDER = 2


class World:
    def __init__(self):
        self.weather_type = WeatherType.CLEAR

    @property
    def weather(self):
        return self.weather_type

    @weather.setter
    def weather(self, value):
        if isinstance(value, int) and 0 <= value < 3:
            self.weather_type = value


class ExprWeather:
    def __init__(self):
        pass

    def init(self, exprs, matched_pattern, is_delayed, parser):
        self.expr = exprs[0]
        return True

    def get(self, event, source):
        if isinstance(event, (dt.datetime, dt.date)):
            world = World()
            weather_type = WeatherType.from_event(event)
            return [weather_type] * len(source)

        for w in source:
            yield from self.get_from_world(w)

    @staticmethod
    def get_from_world(world):
        if 0 <= datetime.now().hour < 12 and isinstance(event, (dt.datetime, dt.date)):
            return WeatherType.RAINY

        # Add more conditions here...

        return world.weather


def to_string(self, event=None, debug=False):
    return f"the weather in {self.expr}"


class ChangeMode:
    DELETE = "delete"
    SET = "set"


def accept_change(self, mode):
    if mode == ChangeMode.DELETE or mode == ChangeMode.SET:
        return [WeatherType]

    return None

def change(self, event, delta=None, mode=ChangeMode.DELETE):
    weather_type = WeatherType.CLEAR
    if delta is not None and isinstance(delta[0], int) and 0 <= delta[0] < 3:
        weather_type = delta[0]
    
    for w in self.expr.get_array(event):
        world = World()
        if event is not None and isinstance(event, (dt.datetime, dt.date)):
            if world == event.world and not Delay.is_delayed(event):
                if isinstance(event, WeatherEvent) or isinstance(event, ThunderChangeEvent):
                    if weather_type == WeatherType.CLEAR:
                        event.set_cancelled(True)
                    elif weather_type == WeatherType.THUNDER:
                        event.get_world().set_thundering(True)

        world.weather = weather_type


def get_return_type(self):
    return WeatherType
