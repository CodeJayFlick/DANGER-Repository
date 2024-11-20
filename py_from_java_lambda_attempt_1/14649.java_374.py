Here is the translation of the Java code to Python:

```Python
class WeatherObserver:
    def __init__(self):
        pass

class HobbitsTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.weather_observer = WeatherObserver()

    def test_hobbits(self):
        for weather, message in [
            (WeatherType.SUNNY, "The hobbits are facing Sunny weather now"),
            (WeatherType.RAINY, "The hobbits are facing Rainy weather now"),
            (WeatherType.WINDY, "The hobbits are facing Windy weather now"),
            (WeatherType.COLD, "The hobbits are facing Cold weather now")
        ]:
            self.weather_observer.update(weather)
            self.assertEqual(self.weather_observer.get_message(), message)

if __name__ == '__main__':
    unittest.main()
```

Note: The Python code does not have direct equivalent of Java's `package`, `import` statements, and some other constructs. It also doesn't include the actual implementation of the WeatherObserver class as it was not provided in the original Java code.