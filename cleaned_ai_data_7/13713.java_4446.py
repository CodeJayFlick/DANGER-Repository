import logging

class ConfigureForDosVisitor:
    def visit(self, hayes):
        logging.info(f"{hayes} used with Dos configurator.")

    def visit(self, zoom):
        logging.info(f"{zoom} used with Dos configurator.")
