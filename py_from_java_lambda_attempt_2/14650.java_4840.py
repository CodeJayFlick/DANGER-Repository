Here is the translation of the Java code to Python:

```Python
class WeatherObserver:
    def __init__(self):
        pass

class OrcsTest(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.weather_observer = WeatherObserver()

    def test_data_provider(self):
        data_providers = [
            {"weather": "SUNNY", "response": "The orcs are facing Sunny weather now"},
            {"weather": "RAINY", "response": "The orcs are facing Rainy weather now"},
            {"weather": "WINDY", "response": "The orcs are facing Windy weather now"},
            {"weather": "COLD", "response": "The orcs are facing Cold weather now"}
        ]
        self.assertEqual(data_providers, WeatherObserver().data_provider())

    def test_new(self):
        pass

if __name__ == '__main__':
    unittest.main()
```

Please note that Python does not have direct equivalent of Java's `package`, `import` statements. Also, the concept of classes and methods in Python is slightly different from those in Java.