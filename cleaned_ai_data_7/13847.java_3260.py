import logging

class SimpleTask:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

    def execute(self):
        self.logger.info("Perform some important activity and after call the callback method.")
