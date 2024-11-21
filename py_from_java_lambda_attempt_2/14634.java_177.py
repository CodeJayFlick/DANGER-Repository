Here is the translation of the Java code to Python:

```Python
import logging

class GOrcs:
    def update(self, weather: str, weather_type: str) -> None:
        logging.info(f"The orcs are facing {weather_type} weather now")

if __name__ == "__main__":
    # You can use this class like below if you want to test it
    go = GOrcs()
    go.update("rainy", "bad")
```

Please note that Python does not have direct equivalent of Java's `@Slf4j` annotation. The logging module in Python is used for the same purpose, but it needs to be configured separately.

Also, Python does not support operator overloading like Java does with its `@Override` annotation.