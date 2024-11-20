import logging

class Commander:
    def __init__(self, unit):
        self.unit = unit

    @property
    def logger(self):
        return logging.getLogger(__name__)

    def commander_ready(self):
        self.logger.info(f"[Commander] {self.unit.name} is ready!")
