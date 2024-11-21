import logging

class TreasureChest:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.info("Treasure chest opens.")

    def close(self):
        self.logger.info("Treasure chest closes.")
