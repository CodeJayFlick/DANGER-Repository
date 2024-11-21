import logging

class SergeantVisitor:
    def visit_soldier(self, soldier):
        # Do nothing
        pass

    def visit_sergeant(self, sergeant):
        logging.info("Hello {}".format(sergeant))

    def visit_commander(self, commander):
        # Do nothing
        pass


if __name__ == "__main__":
    SERGEANT_VISITOR = SergeantVisitor()
