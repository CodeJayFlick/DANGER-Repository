import logging

class GOrcs:
    def update(self, weather: str, weather_type: str) -> None:
        logging.info(f"The orcs are facing {weather_type} weather now")

if __name__ == "__main__":
    # You can use this class like below if you want to test it
    go = GOrcs()
    go.update("rainy", "bad")
