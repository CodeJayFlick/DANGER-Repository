import logging

class SoldierVisitor:
    def visit_soldier(self, soldier):
        logging.info("Greetings {}".format(soldier))

    def visit_serjeant(self, serjeant):
        pass  # Do nothing

    def visit_commander(self, commander):
        pass  # Do nothing


if __name__ == "__main__":
    visitor = SoldierVisitor()
    visitor.visit_soldier("John")
