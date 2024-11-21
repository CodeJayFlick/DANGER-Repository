import logging

class AngryState:
    def __init__(self, mammoth):
        self.mammoth = mammoth

    def observe(self):
        logging.info("{} is furious!".format(self.mammoth))

    def on_enter_state(self):
        logging.info("{} gets angry!".format(self.mammoth))
