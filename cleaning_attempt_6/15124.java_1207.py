import logging

class GameItem:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def draw(self):
        self.logger.info("draw")
        self.do_draw()

    def do_draw(self):
        pass  # abstract method, to be implemented by subclasses

    def click(self):
        pass  # abstract method, to be implemented by subclasses
