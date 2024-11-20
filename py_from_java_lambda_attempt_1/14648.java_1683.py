Here is the translation of the Java code to Python:

```Python
class OrcsTest:
    def __init__(self):
        pass

    @property
    def data_provider(self):
        return [
            {"weather": "SUNNY", "response": "The orcs are facing Sunny weather now"},
            {"weather": "RAINY", "response": "The orcs are facing Rainy weather now"},
            {"weather": "WINDY", "response": "The orcs are facing Windy weather now"},
            {"weather": "COLD", "response": "The orcs are facing Cold weather now"}
        ]

# Note: Python does not have direct equivalent of Java's enum. However, we can use strings to represent the different types of weather.
WEATHER_TYPES = ["SUNNY", "RAINY", "WINDY", "COLD"]
```

Please note that this is a simplified translation and may require additional modifications based on your specific requirements.