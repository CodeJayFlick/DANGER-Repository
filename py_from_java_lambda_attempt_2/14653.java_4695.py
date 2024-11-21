Here is the translation of the Java code to Python:

```Python
import unittest
from unittest.mock import MagicMock, patch
from datetime import timedelta

class WeatherObserver:
    def update(self, weather_type):
        pass


class InMemoryAppender:
    def __init__(self, *args):
        self.log = []

    def stop(self):
        pass

    def get_log_size(self):
        return len(self.log)

    def add_to_log(self, message):
        self.log.append(message)


def time_passes(weather: Weather) -> None:
    weather.time_passes()


class TestWeather(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.appender = InMemoryAppender()

    @classmethod
    def tearDownClass(cls):
        pass

    def setUp(self):
        self.weather = Weather()
        self.weather.add_observer(MagicMock())

    def tearDown(self):
        self.weather.remove_observer(self.weather.observers[0])

    def test_add_remove_observer(self):
        observer = MagicMock(spec=WeatherObserver)
        weather_type = "rainy"
        self.weather.time_passes()
        self.assertEqual("The weather changed to rainy.", self.appender.log[-1])
        observer.update.assert_called_once_with(WeatherType.RAINY)

        self.weather.remove_observer(observer)
        time_passes(self.weather)
        self.assertEqual(f"The weather changed to {weather_type}.", self.appender.log[-1])

    def test_time_passes(self):
        for _ in range(20):
            time_passes(self.weather)


if __name__ == '__main__':
    unittest.main()
```

Note that this is a direct translation of the Java code, and it may not be idiomatic Python.