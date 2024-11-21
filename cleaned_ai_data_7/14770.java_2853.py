import logging

class WizardTowerProxy:
    NUM_WIZARDS_ALLOWED = 3

    def __init__(self, tower):
        self.tower = tower
        self.num_wizards = 0

    @staticmethod
    def log_info(message):
        logging.info(message)

    def enter(self, wizard):
        if self.num_wizards < WizardTowerProxy.NUM_WIZARDS_ALLOWED:
            self.tower.enter(wizard)
            self.num_wizards += 1
        else:
            WizardTowerProxy.log_info(f"{wizard} is not allowed to enter!")
