import logging

class Weather:
    def __init__(self):
        self.current_weather = "SUNNY"
        self.observers = []

    def add_observer(self, observer):
        self.observers.append(observer)

    def remove_observer(self, observer):
        if observer in self.observers:
            self.observers.remove(observer)

    def time_passes(self):
        weather_types = ["SUNNY", "CLOUDY", "RAIN"]
        current_index = list(weather_types).index(self.current_weather)
        next_index = (current_index + 1) % len(weather_types)
        self.current_weather = weather_types[next_index]
        logging.info("The weather changed to %s.", self.current_weather)
        self.notify_observers()

    def notify_observers(self):
        for observer in self.observers:
            observer.update(self.current_weather)

# Example usage
if __name__ == "__main__":
    import logging.config

    # Configure the logger
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    weather = Weather()

    class Observer:
        def update(self, current_weather):
            print(f"Observer: The weather is now {current_weather}.")

    observer1 = Observer()
    observer2 = Observer()

    # Add observers
    weather.add_observer(observer1)
    weather.add_observer(observer2)

    for _ in range(3):  # Simulate time passing three times
        weather.time_passes()
