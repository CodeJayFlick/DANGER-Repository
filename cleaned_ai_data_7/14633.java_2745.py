import logging

class GHobbits:
    def update(self, weather, weather_type):
        logging.info(f"The hobbits are facing {weather_type.description} weather now")

# Usage example:
if __name__ == "__main__":
    # Assuming GWeather and WeatherType classes exist in your project
    g_weather = GWeather()  # Replace with actual instance of GWeather class
    weather_type = WeatherType.SUNNY  # Replace with actual value from WeatherType enum

    ghobbits = GHobbits()
    ghobbits.update(g_weather, weather_type)
