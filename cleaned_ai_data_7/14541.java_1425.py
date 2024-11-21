import logging

class GiantView:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

    def display_giant(self, giant_model: 'GiantModel') -> None:
        self.logger.info(str(giant_model))
