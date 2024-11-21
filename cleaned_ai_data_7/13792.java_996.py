import logging

class FlyingEnchantment:
    def on_activate(self):
        logging.info("The item begins to glow faintly.")

    def apply(self):
        logging.info("The item flies and strikes the enemies finally returning to owner's hand.")

    def on_deactivate(self):
        logging.info("The item's glow fades.")
