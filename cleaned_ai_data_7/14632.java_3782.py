import logging

class Weather:
    def __init__(self):
        self.observers = []

    def addObserver(self, observer):
        self.observers.append(observer)

    def timePasses(self):
        for observer in self.observers:
            observer.update()

logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)

class Orcs:
    def update(self):
        LOGGER.info("Orcs: Weather has changed")

class Hobbits:
    def update(self):
        LOGGER.info("Hobbits: Weather has changed")

def main():
    weather = Weather()
    weather.addObserver(Orcs())
    weather.addObserver(Hobbits())

    for _ in range(4):  # Simulate time passing
        weather.timePasses()

    # Generic observer inspired by Java Generics and Collections by Naftalin & Wadler
    LOGGER.info("--Running generic version--")
    generic_weather = Weather()
    generic_weather.addObserver(Orcs())
    generic_weather.addObserver(Hobbits())

    for _ in range(4):  # Simulate time passing
        generic_weather.timePasses()

if __name__ == "__main__":
    main()
