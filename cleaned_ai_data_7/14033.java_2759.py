import logging

class Tobacco:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def smoke(self, wizard: 'Wizard') -> None:
        self.logger.info("{} smoking {}".format(wizard.__class__.__name__, type(self).__name__))

