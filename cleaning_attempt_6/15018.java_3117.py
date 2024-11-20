import logging

class Mammoth:
    pass


class PeacefulState:
    def __init__(self, mammoth):
        self.mammoth = mammoth

    @property
    def logger(self):
        return logging.getLogger(__name__)

    def observe(self):
        self.logger.info("{} is calm and peaceful.".format(self.mammoth))

    def on_enter_state(self):
        self.logger.info("{} calms down.".format(self.mammoth))
