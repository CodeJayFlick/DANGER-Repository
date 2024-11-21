import logging

class HolderNaive:
    def __init__(self):
        self.heavy = None
        logging.info("HolderNaive created")

    @property
    def heavy(self):
        if self.heavy is None:
            self.heavy = Heavy()
        return self.heavy


class Heavy:
    pass  # No implementation needed for this example, just a placeholder class
