import logging

class SoulEatingEnchantment:
    def __init__(self):
        self.logger = logging.getLogger(__name__)

    def on_activate(self):
        self.logger.info("The item spreads bloodlust.")

    def apply(self):
        self.logger.info("The item eats the soul of enemies.")

    def on_deactivate(self):
        self.logger.info("Bloodlust slowly disappears.")
