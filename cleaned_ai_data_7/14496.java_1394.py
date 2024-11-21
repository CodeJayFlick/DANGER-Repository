import logging

class Guard:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def enter(self):
        self.logger.info("You can enter")
