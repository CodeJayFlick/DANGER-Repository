import logging

class FishingBoat:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def sail(self):
        self.logger.info("The fishing boat is sailing")

# Usage example
if __name__ == "__main__":
    boat = FishingBoat()
    boat.sail()
