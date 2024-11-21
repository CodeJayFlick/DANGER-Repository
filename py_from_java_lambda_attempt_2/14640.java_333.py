Here is the translation of the Java code to Python:

```Python
import logging

class Orcs:
    def update(self, current_weather):
        logging.info(f"The orcs are facing {current_weather.description} weather now")

if __name__ == "__main__":
    # You can use this as a main function if you want to test your class.
    pass
```

Note that Python does not have direct equivalent of Java's `@Slf4j` annotation. The logging module in Python is used for logging purposes, and it needs to be configured separately.

Also note that the concept of interfaces (like `WeatherObserver`) are implemented using abstract classes or inheritance in Python.