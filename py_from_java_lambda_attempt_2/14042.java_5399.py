Here is the translation of the Java code to Python:

```Python
import logging
import time
from threading import Timer

class World:
    def __init__(self):
        self.countries = []

    def fetch(self):
        # Simulate fetching countries from a file or database
        return ["Country 1", "Country 2", "Country 3"]

def main():
    logging.basicConfig(level=logging.INFO)
    LOGGER = logging.getLogger(__name__)

    world = World()
    app = App()

    while True:
        countries = world.fetch()
        print("Our world currently has the following countries:")
        for country in countries:
            print("\t" + country)

        time.sleep(15)  # Run at every 15 seconds

class App:
    def run(self):
        Timer(0, self.update_world).start()

    def update_world(self):
        world = World()
        countries = world.fetch()
        LOGGER.info("Our world currently has the following countries:")
        for country in countries:
            print("\t" + country)

if __name__ == "__main__":
    app = App()
    app.run()
```

Please note that Python does not have a direct equivalent to Java's `Executors` and `TimeUnit`. Instead, we use Python's built-in `time.sleep()` function for scheduling tasks.