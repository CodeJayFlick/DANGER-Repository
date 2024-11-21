import logging

class SlidingDoor:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.info("Sliding door opens.")

    def close(self):
        self.logger.info("Sliding door closes.")
